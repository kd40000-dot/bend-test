#!/usr/bin/env python3
"""Repack, patch and v1+v2-sign a user-provided Bend 7.6.6 APK."""
import argparse
import datetime
import hashlib
import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from patchdex import patch

MAGIC = b'APK Sig Block 42'
V2_ID = 0x7109871a
ALG = 0x0103  # RSA-PKCS1-v1_5 with SHA-256
CHUNK_SIZE = 1024 * 1024

def lp(data):
    return struct.pack('<I', len(data)) + data

def repack(src, dst, patch_dex=False, remove_old_signatures=False):
    """Preserve all app contents and compression; align stored resources.arsc."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, 'w') as zout:
        zout.comment = zin.comment
        changed = False
        for entry in zin.infolist():
            name = entry.filename
            upper = name.upper()
            if remove_old_signatures and upper.startswith('META-INF/') and (
                upper.endswith(('.RSA', '.DSA', '.EC', '.SF')) or upper == 'META-INF/MANIFEST.MF'
            ):
                continue
            data = zin.read(entry)
            if patch_dex and name == 'classes.dex':
                data, method_id = patch(data)
                print('Patched classes.dex method index:', method_id)
                changed = True
            zi = zipfile.ZipInfo(name, entry.date_time)
            zi.compress_type = entry.compress_type
            zi.comment = entry.comment
            zi.external_attr = entry.external_attr
            zi.internal_attr = entry.internal_attr
            zi.create_system = entry.create_system
            zi.create_version = entry.create_version
            zi.extract_version = entry.extract_version
            if name == 'resources.arsc' and zi.compress_type == zipfile.ZIP_STORED:
                current = zout.fp.tell()
                header_len = 30 + len(name.encode('utf8'))
                pad = (-current - header_len) % 4
                if pad and pad < 4:
                    pad += 4
                if pad:
                    zi.extra = struct.pack('<HH', 0xd935, pad - 4) + bytes(pad - 4)
            zout.writestr(zi, data)
        if patch_dex and not changed:
            raise RuntimeError('classes.dex not found')

def key_or_create(path, password):
    path = pathlib.Path(path)
    if path.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Bend Background Timer Patch')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    result = pkcs12.serialize_key_and_certificates(
        b'bendpatch', key, cert, None,
        serialization.BestAvailableEncryption(password.encode()))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(result)
    os.chmod(path, 0o600)
    print('Created private signing key:', path)

def sign_v1(src, dst, key, password):
    subprocess.run([
        'jarsigner', '-keystore', str(key), '-storetype', 'PKCS12',
        '-storepass', password, '-keypass', password,
        '-sigalg', 'SHA256withRSA', '-digestalg', 'SHA-256',
        '-sigfile', 'BENDPATCH', '-signedjar', str(dst),
        str(src), 'bendpatch',
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def eocd_offset(apk):
    for i in range(len(apk)-22, max(-1, len(apk)-22-65536), -1):
        if (apk[i:i+4] == b'PK\x05\x06'
                and i + 22 + struct.unpack_from('<H', apk, i+20)[0] == len(apk)):
            return i
    raise ValueError('ZIP end of central directory not found')

def apk_digest(sections):
    chunks = []
    for section in sections:
        for pos in range(0, len(section), CHUNK_SIZE):
            part = section[pos:pos+CHUNK_SIZE]
            chunks.append(hashlib.sha256(
                b'\xa5' + struct.pack('<I', len(part)) + part).digest())
    return hashlib.sha256(b'Z' + struct.pack('<I', len(chunks))
                          + b''.join(chunks)).digest()

def sign_v2(src, dst, keyfile, password):
    key, cert, _ = pkcs12.load_key_and_certificates(
        pathlib.Path(keyfile).read_bytes(), password.encode())
    original = pathlib.Path(src).read_bytes()
    eocd = eocd_offset(original)
    cd = struct.unpack_from('<I', original, eocd+16)[0]
    if original[cd:cd+4] != b'PK\x01\x02':
        raise ValueError('Cannot sign unexpected ZIP layout')
    before = original[:cd]
    directory = original[cd:eocd]
    ending = bytearray(original[eocd:])
    digest = apk_digest([before, directory, ending])
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed_data = (lp(lp(struct.pack('<I', ALG) + lp(digest)))
                   + lp(lp(cert_der)) + lp(b''))
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    signer = (lp(signed_data)
              + lp(lp(struct.pack('<I', ALG) + lp(signature)))
              + lp(key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)))
    value = lp(lp(signer))
    pair = struct.pack('<Q', 4 + len(value)) + struct.pack('<I', V2_ID) + value
    size = len(pair) + 24
    block = struct.pack('<Q', size) + pair + struct.pack('<Q', size) + MAGIC
    struct.pack_into('<I', ending, 16, cd + len(block))
    pathlib.Path(dst).write_bytes(before + block + directory + ending)

def check_apk(path):
    """Verify v2 block structure, RSA signature, APK digest and ZIP CRCs."""
    data = pathlib.Path(path).read_bytes()
    end = eocd_offset(data)
    cd = struct.unpack_from('<I', data, end + 16)[0]
    assert data[cd:cd+4] == b'PK\x01\x02'
    assert data[cd-16:cd] == MAGIC
    size = struct.unpack_from('<Q', data, cd-24)[0]
    start = cd-size-8
    assert struct.unpack_from('<Q', data, start)[0] == size
    length = struct.unpack_from('<Q', data, start+8)[0]
    assert struct.unpack_from('<I', data, start+16)[0] == V2_ID
    value = data[start+20:start+20+length-4]

    def read_lp(buf, pos):
        n = struct.unpack_from('<I', buf, pos)[0]
        return buf[pos+4:pos+4+n], pos+4+n

    signers, _ = read_lp(value, 0)
    signer, _ = read_lp(signers, 0)
    signed, pos = read_lp(signer, 0)
    signatures, pos = read_lp(signer, pos)
    pub, pos = read_lp(signer, pos)
    assert pos == len(signer)
    signature_record, _ = read_lp(signatures, 0)
    assert struct.unpack_from('<I', signature_record, 0)[0] == ALG
    signature, _ = read_lp(signature_record, 4)
    digests, pos = read_lp(signed, 0)
    certificates, pos = read_lp(signed, pos)
    attrs, pos = read_lp(signed, pos)
    assert not attrs
    digest_record, _ = read_lp(digests, 0)
    assert struct.unpack_from('<I', digest_record, 0)[0] == ALG
    digest, _ = read_lp(digest_record, 4)
    cert_der, _ = read_lp(certificates, 0)
    cert = x509.load_der_x509_certificate(cert_der)
    assert cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo) == pub
    cert.public_key().verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    ending = bytearray(data[end:])
    struct.pack_into('<I', ending, 16, start)
    assert apk_digest([data[:start], data[cd:end], ending]) == digest
    with zipfile.ZipFile(path) as z:
        assert z.testzip() is None
        entry = z.getinfo('resources.arsc')
        with open(path, 'rb') as handle:
            handle.seek(entry.header_offset + 26)
            n, x = struct.unpack('<HH', handle.read(4))
        assert (entry.header_offset + 30 + n + x) % 4 == 0
        dex = z.read('classes.dex')
        assert hashlib.sha1(dex[32:]).digest() == dex[12:32]
    subprocess.run(['jarsigner', '-verify', str(path)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print('Validated APK ZIP, DEX, v1 signature, v2 RSA signature and digest')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('original')
    parser.add_argument('output')
    parser.add_argument('--key', default='private/BendPatch.p12')
    parser.add_argument('--password', required=True)
    args = parser.parse_args()
    key_or_create(args.key, args.password)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        unsigned = root/'unsigned.apk'
        v1 = root/'signed-v1.apk'
        aligned = root/'aligned-v1.apk'
        repack(args.original, unsigned, patch_dex=True, remove_old_signatures=True)
        sign_v1(unsigned, v1, args.key, args.password)
        repack(v1, aligned)  # jarsigner can change ZIP alignment
        sign_v2(aligned, args.output, args.key, args.password)
    check_apk(args.output)
    print('Created:', args.output)

if __name__ == '__main__':
    main()

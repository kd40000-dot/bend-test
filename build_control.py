#!/usr/bin/env python3
"""Build original-bytecode, replacement-signature diagnostic control APK.

Run in the same directory as build.py, alongside your locally held original
APK and private signing key. This leaves ALL original code and asset bytes
unchanged, omitting only pre-existing META-INF signature records.
"""
import argparse
import pathlib
import struct
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_STORED
import build

def prepare_control(source, destination):
    with ZipFile(source) as src, ZipFile(destination, 'w') as dst:
        for item in src.infolist():
            name = item.filename
            upper = name.upper()
            if upper.startswith('META-INF/') and (
                upper.endswith(('.RSA', '.DSA', '.EC', '.SF'))
                or upper == 'META-INF/MANIFEST.MF'
            ):
                continue
            info = ZipInfo(name, item.date_time)
            info.compress_type = item.compress_type
            info.comment = item.comment
            info.external_attr = item.external_attr
            info.internal_attr = item.internal_attr
            info.create_system = item.create_system
            info.create_version = item.create_version
            info.extract_version = item.extract_version
            if info.compress_type == ZIP_STORED:
                offset = dst.fp.tell()
                padding = (-offset - 30 - len(name.encode('utf8'))) % 4
                if padding:
                    padding += 4
                    info.extra = struct.pack('<HH', 0xd935, padding - 4) + bytes(padding - 4)
            dst.writestr(info, src.read(item))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('original')
    parser.add_argument('output')
    parser.add_argument('--key', default='private/BendPatch.p12')
    parser.add_argument('--password', required=True)
    args = parser.parse_args()
    key = pathlib.Path(args.key)
    if not key.exists():
        raise SystemExit('Existing v2 signing key is required; do not generate a different one.')
    with tempfile.TemporaryDirectory() as temp:
        unsigned = pathlib.Path(temp) / 'unsigned.apk'
        signed = pathlib.Path(temp) / 'signed.apk'
        aligned = pathlib.Path(temp) / 'aligned.apk'
        prepare_control(args.original, unsigned)
        build.sign_v1(unsigned, signed, key, args.password)
        build.repack(signed, aligned)
        build.sign_v2(aligned, args.output, key, args.password)
    build.check_apk(args.output)
    with ZipFile(args.original) as old, ZipFile(args.output) as new:
        for name in old.namelist():
            if not name.upper().startswith('META-INF/'):
                assert old.read(name) == new.read(name), name
    print('Control APK verified: original non-signature files unchanged.')

if __name__ == '__main__':
    main()

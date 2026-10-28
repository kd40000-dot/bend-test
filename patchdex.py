"""Patch Bend 7.6.6's repeating Java timer to fixed-rate scheduling."""
import hashlib
import struct
import zlib
from dexinspect import Dex

def patch(b):
    d = Dex(b)
    old = 'schedule'
    new = 'scheduleAtFixedRate'
    if old not in d.strings or new not in d.strings:
        raise RuntimeError('Unexpected DEX string table')
    matches = [
        i for i, (c, p, n) in enumerate(d.methods)
        if d.types[c] == 'Ljava/util/Timer;'
        and d.strings[n] == old
        and d.proto(p) == 'Ljava/util/TimerTask;JJ'
    ]
    if len(matches) != 1:
        raise RuntimeError('Unexpected Timer.schedule reference count: %s' % matches)
    idx = matches[0]
    pos = d.ui(0x5c) + 8 * idx + 4
    data = bytearray(b)
    assert struct.unpack_from('<I', data, pos)[0] == d.strings.index(old)
    struct.pack_into('<I', data, pos, d.strings.index(new))
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data), idx

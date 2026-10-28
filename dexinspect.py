"""Minimal Dalvik DEX reader for identifying method references."""
import struct

class Dex:
    def __init__(self, b):
        self.b = b
        self.ui = lambda o: struct.unpack_from('<I', b, o)[0]
        self.uh = lambda o: struct.unpack_from('<H', b, o)[0]
        self.strings = []
        n, o = self.ui(0x38), self.ui(0x3c)
        for i in range(n):
            at = self.ui(o + i * 4)
            _, at = self.leb(at)
            end = b.find(b'\0', at)
            self.strings.append(b[at:end].decode('utf8', 'replace'))
        n, o = self.ui(0x40), self.ui(0x44)
        self.types = [self.strings[self.ui(o + i * 4)] for i in range(n)]
        n, o = self.ui(0x48), self.ui(0x4c)
        self.protos = [tuple(self.ui(o + i * 12 + j * 4) for j in range(3)) for i in range(n)]
        n, o = self.ui(0x58), self.ui(0x5c)
        self.methods = [
            (self.uh(o + i*8), self.uh(o + i*8 + 2), self.ui(o + i*8 + 4))
            for i in range(n)
        ]

    def leb(self, o):
        result = 0
        for i in range(5):
            value = self.b[o]
            o += 1
            result |= (value & 127) << (7 * i)
            if value < 128:
                break
        return result, o

    def proto(self, idx):
        _, _, off = self.protos[idx]
        if not off:
            return ''
        n = self.ui(off)
        return ''.join(self.types[self.uh(off + 4 + i*2)] for i in range(n))

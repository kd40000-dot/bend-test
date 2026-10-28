"""Target ONLY the Bend 7.6.6 workout countdown lifecycle stop.

On Android ON_STOP, Bend's Lfr1.i lifecycle observer invokes Lfn0.d().
That cancels the Timer AND resets remaining time back to the initial
duration. Replace only this invocation with three Dalvik NOP words.
All manual pause/stop controls and unrelated timers remain unchanged.
"""
import hashlib
import struct
import zlib
from dexinspect import Dex

TARGET = 'Lfr1;->i(Lm45;Lc45;)'
STOP = 'Lfn0;->d()'
START = 'Lfn0;->c(Lfn0;)'

def patch(original):
    dex = Dex(original)
    matches = [i for i, method in enumerate(dex.methods)
               if dex.method_name(i) == TARGET]
    if len(matches) != 1:
        raise ValueError('Unexpected lifecycle method match: %r' % matches)
    start = [i for i in range(len(dex.methods)) if dex.method_name(i) == START]
    stop = [i for i in range(len(dex.methods)) if dex.method_name(i) == STOP]
    if len(start) != 1 or len(stop) != 1:
        raise ValueError('Missing expected workout timer start/stop methods')
    code_off = dex.get_code_offsets().get(matches[0])
    if code_off is None:
        raise ValueError('Lifecycle method has no code')
    code_size = dex.ui(code_off + 12) * 2
    code = original[code_off + 16:code_off + 16 + code_size]
    stop_insn = bytes((0x6e, 0x10)) + struct.pack('<H', stop[0]) + b'\x00\x00'
    start_insn = bytes((0x71, 0x10)) + struct.pack('<H', start[0]) + b'\x00\x00'
    if code.count(stop_insn) != 1 or code.count(start_insn) != 1:
        raise ValueError('Unexpected lifecycle start/stop calls; refusing unsafe patch')
    offset = code_off + 16 + code.index(stop_insn)
    result = bytearray(original)
    result[offset:offset+6] = bytes(6)
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into('<I', result, 8, zlib.adler32(result[12:]) & 0xffffffff)
    return bytes(result), offset

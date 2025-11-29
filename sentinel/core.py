import math
import struct
import binascii
from collections import Counter

class FastMath:
    @staticmethod
    def entropy(data):
        if not data: return 0
        len_data = len(data)
        counts = Counter(data)
        ent = 0.0
        for count in counts.values():
            p = count / len_data
            if p > 0: ent -= p * math.log2(p)
        return ent

class ArchID:
    """Standard Lib implementation of CPU Architecture Fingerprinting."""
    @staticmethod
    def identify(data):
        if not data: return "Empty Region"
        length = len(data)
        if length < 4: return "Too small to analyze"

        if data.startswith(b'MZ'): return "Windows PE Header (x86/64)"
        if data.startswith(b'\x7fELF'):
            return "Linux ELF Header " + ("(64-bit)" if data[4] == 2 else "(32-bit)")
        if data.startswith(b'\xca\xfe\xba\xbe') or data.startswith(b'\xfe\xed\xfa\xce'):
            return "Mac Mach-O Header"
        if data.startswith(b'%PDF'): return "PDF Document Header"
        
        # Entropy & Text Checks
        ent = FastMath.entropy(data)
        printable = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        if printable / length > 0.90: return "ASCII Text / Source Code"
        if ent < 1.0: return "Null Padding / Zero Space"
        if ent > 7.9: return "High Entropy (Crypto/Compressed)"

        # Simple Heuristics for binary code
        counts = Counter(data)
        def freq(byte_val): return counts.get(byte_val, 0) / length
        score_x86 = freq(0xC3) * 5 + freq(0x90) * 3 + freq(0x55) * 2 + freq(0x89)
        score_x64 = score_x86 + (freq(0x48) * 3)
        score_arm64 = 0
        if length > 8:
            nulls_aligned = sum(1 for i in range(3, length, 4) if data[i] == 0)
            score_arm64 = (nulls_aligned / (length/4)) * 2.5
        
        scores = {"x86 (32-bit)": score_x86, "x86_64 (64-bit)": score_x64, "ARM64": score_arm64}
        best_arch = max(scores, key=scores.get)
        if scores[best_arch] < 0.05: return "Unknown Binary Data"
        return best_arch + " Code (Probable)"

class BMPGenerator:
    @staticmethod
    def create_bmp(rgb_tuples):
        count = len(rgb_tuples)
        if count == 0: return b''
        width = int(math.ceil(math.sqrt(count)))
        height = int(math.ceil(count / width))
        row_size = (width * 3 + 3) & ~3
        pixel_array_size = row_size * height
        file_size = 54 + pixel_array_size
        header = struct.pack('<2sIHHI', b'BM', file_size, 0, 0, 54)
        dib = struct.pack('<IiihhIIIIII', 40, width, -height, 1, 24, 0, pixel_array_size, 2835, 2835, 0, 0)
        pixel_data = bytearray()
        for y in range(height):
            row_data = bytearray()
            for x in range(width):
                idx = y * width + x
                if idx < count:
                    r_f, g_f, b_f = rgb_tuples[idx]
                    row_data.extend([min(255, int(b_f*255)), min(255, int(g_f*255)), min(255, int(r_f*255))])
                else:
                    row_data.extend([0, 0, 0])
            row_data.extend([0] * ((4 - (len(row_data) % 4)) % 4))
            pixel_data.extend(row_data)
        return header + dib + pixel_data

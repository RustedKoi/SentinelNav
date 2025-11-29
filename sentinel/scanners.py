class Scanner:
    def yield_raw_chunks(self, path): raise NotImplementedError

class FixedScanner(Scanner):
    def __init__(self, block_size):
        self.block_size = block_size
    def yield_raw_chunks(self, path):
        offset = 0
        with open(path, 'rb') as f:
            while True:
                data = f.read(self.block_size)
                if not data: break
                yield (offset, data)
                offset += len(data)

class SentinelScanner(Scanner):
    def __init__(self, delimiter_byte, max_size):
        self.delimiter = delimiter_byte
        self.max_size = max_size
    def yield_raw_chunks(self, path):
        offset = 0
        with open(path, 'rb') as f:
            buffer = bytearray()
            while True:
                read_chunk = f.read(65536)
                if not read_chunk and not buffer: break
                if read_chunk: buffer.extend(read_chunk)
                while len(buffer) > 0:
                    idx = buffer.find(self.delimiter)
                    cut_len = idx + 1 if idx != -1 else (self.max_size if len(buffer) >= self.max_size else len(buffer))
                    if idx == -1 and read_chunk and len(buffer) < self.max_size: break
                    if idx != -1 and cut_len > self.max_size: cut_len = self.max_size
                    
                    yield (offset, bytes(buffer[:cut_len]))
                    offset += cut_len
                    del buffer[:cut_len]

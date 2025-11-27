import math
import os
import sys
import json
import argparse
import http.server
import socketserver
import urllib.parse
import sqlite3
import tempfile
import threading
import concurrent.futures
import struct
import binascii
from collections import Counter

# --- 1. ARCHITECTURE FORENSICS (HEURISTICS) ---

class ArchID:
    """
    Standard Lib implementation of CPU Architecture Fingerprinting.
    """
    @staticmethod
    def identify(data):
        if not data: return "Empty Region"

        length = len(data)
        if length < 4: return "Too small to analyze"

        # 1. Check Magic Bytes (Headers)
        # These are authoritative if found at the start of a chunk
        if data.startswith(b'MZ'): return "Windows PE Header (x86/64)"
        if data.startswith(b'\x7fELF'):
            return "Linux ELF Header " + ("(64-bit)" if data[4] == 2 else "(32-bit)")
        if data.startswith(b'\xca\xfe\xba\xbe') or data.startswith(b'\xfe\xed\xfa\xce'):
            return "Mac Mach-O Header"
        if data.startswith(b'%PDF'): return "PDF Document Header"
        if data.startswith(b'\x89PNG'): return "PNG Image Header"
        if data.startswith(b'\xff\xd8\xff'): return "JPEG Image Header"

        # 2. Entropy Check (Code vs Data)
        ent = FastMath.entropy(data)
        if ent < 1.0: return "Null Padding / Zero Space"
        if ent < 3.0: return "Low Entropy (Sparse Data)"
        if ent > 7.9: return "High Entropy (Crypto/Compressed)"

        # 3. ASCII / Text Check
        # Calculate ratio of printable characters
        printable = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
        if printable / length > 0.90:
            return "ASCII Text / Source Code"

        # 4. Machine Code Heuristics (Frequency Analysis)
        # We only check this if it's not text and has "code-like" entropy (approx 5.0 - 7.0)

        counts = Counter(data)
        def freq(byte_val): return counts.get(byte_val, 0) / length

        # x86 / x64 Signatures
        # 0xC3 (RET), 0x90 (NOP), 0x55 (PUSH EBP), 0x89 (MOV), 0x48 (REX.W)
        score_x86 = freq(0xC3) * 5 + freq(0x90) * 3 + freq(0x55) * 2 + freq(0x89)
        score_x64 = score_x86 + (freq(0x48) * 3)

        # ARM64 (AArch64) Signatures
        # ARM instructions are 4-byte aligned. We look for alignment patterns of null bytes
        # often found in upper bits of instructions or specific opcodes.
        score_arm64 = 0
        if length > 8:
            # Check for 4-byte alignment of 0x00 (common in little-endian ARM instructions)
            nulls_aligned = sum(1 for i in range(3, length, 4) if data[i] == 0)
            score_arm64 = (nulls_aligned / (length/4)) * 2.5

        scores = {
            "x86 (32-bit)": score_x86,
            "x86_64 (64-bit)": score_x64,
            "ARM64 / AArch64": score_arm64
        }

        best_arch = max(scores, key=scores.get)

        # Threshold: If scores are too low, it's likely just binary data, not code
        if scores[best_arch] < 0.05:
            if ent > 6.0: return "Unknown High Density Data"
            return "Unknown Binary Data"

        return best_arch + " Code (Probable)"

# --- 2. GLOBAL STATE & DB ---

SERVER_FILE_PATH = None
SERVER_CONFIG = None
DB_PATH = None
ENGINE = None

class DataEngine:
    def __init__(self):
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = self.tmp_db.name
        self.tmp_db.close()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                offset INTEGER,
                length INTEGER,
                entropy REAL,
                r_val REAL,
                g_val REAL,
                b_val REAL,
                anom_score REAL,
                flux_type INTEGER
            )
        """)
        self.cursor.execute("CREATE INDEX idx_id ON chunks(id)")
        self.conn.commit()

    def insert_bulk(self, data_tuples):
        self.cursor.executemany(
            "INSERT INTO chunks (offset, length, entropy, r_val, g_val, b_val, anom_score, flux_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            data_tuples
        )
        self.conn.commit()

    def get_page(self, page_num, page_size):
        offset = page_num * page_size
        self.cursor.execute(
            "SELECT offset, length, entropy, r_val, g_val, b_val, anom_score, flux_type FROM chunks LIMIT ? OFFSET ?",
            (page_size, offset)
        )
        rows = self.cursor.fetchall()
        chunks = []
        anoms = []
        for r in rows:
            chunks.append((r[0], r[1], r[2], r[3], r[4], r[5]))
            anoms.append((round(r[6], 2), r[7]))
        return chunks, anoms

    def get_all_spectral_data(self):
        self.cursor.execute("SELECT r_val, g_val, b_val FROM chunks ORDER BY id ASC")
        return self.cursor.fetchall()

    def get_total_count(self):
        self.cursor.execute("SELECT COUNT(*) FROM chunks")
        result = self.cursor.fetchone()
        return result[0] if result else 0

    def close(self):
        self.conn.close()
        try: os.unlink(self.db_path)
        except: pass

# --- 3. WORKER & PROCESSOR & BMP ---

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
                    r = min(255, int(r_f * 255))
                    g = min(255, int(g_f * 255))
                    b = min(255, int(b_f * 255))
                    row_data.extend([b, g, r])
                else:
                    row_data.extend([0, 0, 0])
            padding = (4 - (len(row_data) % 4)) % 4
            row_data.extend([0] * padding)
            pixel_data.extend(row_data)
        return header + dib + pixel_data

def _worker_scan(args):
    offset, data = args
    if not data: return (offset, 0, 0.0, 0.0, 0.0, 0.0)
    length = len(data)
    ent = FastMath.entropy(data)
    counts = Counter(data)
    r_count = 0
    g_count = 0
    b_count = 0
    for byte_val, count in counts.items():
        if 0x80 <= byte_val <= 0xFF:
            r_count += count
        elif 0x20 <= byte_val <= 0x7E:
            g_count += count
        elif 0x00 <= byte_val <= 0x1F:
            b_count += count
    return (offset, length, round(ent, 3),
            round(r_count/length, 3),
            round(g_count/length, 3),
            round(b_count/length, 3))

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
                    cut_len = 0
                    if idx != -1:
                        cut_len = idx + 1
                        if cut_len > self.max_size: cut_len = self.max_size
                    else:
                        if len(buffer) >= self.max_size: cut_len = self.max_size
                        elif not read_chunk: cut_len = len(buffer)
                        else: break
                    chunk_data = buffer[:cut_len]
                    yield (offset, bytes(chunk_data))
                    offset += cut_len
                    del buffer[:cut_len]

class Processor:
    @staticmethod
    def run(scanner, target_file, window_size=5):
        global ENGINE
        if ENGINE: ENGINE.close()
        ENGINE = DataEngine()
        file_size = os.path.getsize(target_file)
        workers = max(1, (os.cpu_count() or 1) - 1)
        print(f"[+] Scanning {file_size/1024/1024:.2f} MB using {workers} parallel workers...")

        hist_ent = []
        batch_buffer = []
        count = 0
        prev_ent = 0.0

        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
            chunk_gen = scanner.yield_raw_chunks(target_file)
            results_iter = executor.map(_worker_scan, chunk_gen, chunksize=20)

            for offset, length, ent, r, g, b in results_iter:
                anom_score = 0.0
                flux_type = 0
                if len(hist_ent) >= window_size:
                    avg = sum(hist_ent) / len(hist_ent)
                    diff = abs(ent - avg)
                    anom_score = min(1.0, diff / 2.0)
                delta = ent - prev_ent
                if delta > 1.5 and ent > 6.0:
                    flux_type = 1
                    anom_score += 0.8
                elif delta < -1.5 and ent < 3.0:
                    flux_type = 2
                    anom_score += 0.8
                elif ent > 7.95:
                    flux_type = 3
                    anom_score += 0.5

                prev_ent = ent
                hist_ent.append(ent)
                if len(hist_ent) > (window_size * 2): hist_ent.pop(0)

                batch_buffer.append((offset, length, ent, r, g, b, anom_score, flux_type))
                count += 1
                if len(batch_buffer) >= 2000:
                    ENGINE.insert_bulk(batch_buffer)
                    batch_buffer = []
                    sys.stdout.write(f"\r    Processed {count} blocks...")
                    sys.stdout.flush()

        if batch_buffer: ENGINE.insert_bulk(batch_buffer)
        print(f"\n[+] Scan complete. Total blocks: {count}")

# --- 4. SERVER & REPORTING ---

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class ByteServer(http.server.BaseHTTPRequestHandler):
    html_content = ""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/read":
            try:
                offset = int(query['offset'][0])
                length = min(int(query['length'][0]), 8192)
                with open(SERVER_FILE_PATH, 'rb') as f:
                    f.seek(offset)
                    data = f.read(length)

                # IMPLEMENTATION OF ARCH ID USAGE
                arch_guess = ArchID.identify(data)
                self.send_json({"hex": data.hex(), "arch": arch_guess})
            except Exception as e: self.send_error(500, str(e))

        elif parsed.path == "/search":
            try:
                hex_str = query['hex'][0].replace(" ", "").replace("0x", "")
                needle = binascii.unhexlify(hex_str)
                found_offset = -1
                with open(SERVER_FILE_PATH, 'rb') as f:
                    chunk_size = 1024 * 1024
                    pos = 0
                    while True:
                        data = f.read(chunk_size)
                        if not data: break
                        idx = data.find(needle)
                        if idx != -1:
                            found_offset = pos + idx
                            break
                        if len(data) == chunk_size:
                            f.seek(-(len(needle)-1), 1)
                            pos = f.tell()
                        else:
                            pos += len(data)
                if found_offset != -1:
                    self.send_json({"found": True, "offset": found_offset})
                else:
                    self.send_json({"found": False})
            except Exception as e:
                self.send_json({"found": False, "error": str(e)})

        elif parsed.path == "/download":
            try:
                mode = query.get('mode', ['bin'])[0]
                if mode == "bmp":
                    rgb_data = ENGINE.get_all_spectral_data()
                    bmp_bytes = BMPGenerator.create_bmp(rgb_data)
                    fn = "scan_visualization.bmp"
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/bmp')
                    self.send_header('Content-Disposition', f'attachment; filename="{fn}"')
                    self.send_header('Content-Length', str(len(bmp_bytes)))
                    self.end_headers()
                    self.wfile.write(bmp_bytes)
                elif mode == "txt":
                    offset = int(query['offset'][0])
                    length = int(query['length'][0])
                    fn = f"extract_{offset:X}.txt"
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_header('Content-Disposition', f'attachment; filename="{fn}"')
                    self.end_headers()
                    with open(SERVER_FILE_PATH, 'rb') as f:
                        f.seek(offset)
                        data = f.read(min(length, 16384))
                    report = []
                    report.append(f"SENTINEL NAV EXTRACT REPORT")
                    report.append(f"Offset: 0x{offset:X} | Length: {length} bytes")
                    report.append(f"Analysis: {ArchID.identify(data)}")
                    report.append("-" * 40)
                    report.append("HEX DUMP (First 16KB max):")
                    hex_str = data.hex()
                    for i in range(0, len(hex_str), 32):
                        report.append(hex_str[i:i+32])
                    self.wfile.write("\n".join(report).encode())
                else:
                    offset = int(query['offset'][0])
                    length = int(query['length'][0])
                    fn = f"extract_{offset:X}.bin"
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename="{fn}"')
                    self.send_header('Content-Length', str(length))
                    self.end_headers()
                    with open(SERVER_FILE_PATH, 'rb') as f:
                        f.seek(offset)
                        sent = 0
                        while sent < length:
                            chunk = f.read(min(65536, length - sent))
                            if not chunk: break
                            self.wfile.write(chunk)
                            sent += len(chunk)
            except Exception as e:
                print(e)
                self.send_error(500)

        elif parsed.path == "/data":
            try:
                p = int(query.get('page', ['0'])[0])
                ps = int(query.get('size', ['5000'])[0])
                chunks, anoms = ENGINE.get_page(p, ps)
                self.send_json({"chunks": chunks, "anom": anoms, "total": ENGINE.get_total_count()})
            except Exception as e: self.send_error(500, str(e))
        elif parsed.path == "/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            content = ReportGenerator.get_html(SERVER_FILE_PATH, SERVER_CONFIG['name'], True)
            self.wfile.write(content.encode('utf-8'))
        else: self.send_error(404)

    def do_POST(self):
        if self.path == "/load":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            params = urllib.parse.parse_qs(post_data.decode('utf-8'))
            new_path = params.get('filepath', [''])[0]
            if os.path.exists(new_path) and os.path.isfile(new_path):
                global SERVER_FILE_PATH
                SERVER_FILE_PATH = new_path
                conf = SERVER_CONFIG
                if conf["mode"] == "FIXED":
                    scanner = FixedScanner(conf["size"])
                else:
                    try:
                        hx = conf.get("hex", "00")
                        scanner = SentinelScanner(bytes.fromhex(hx), conf["size"])
                    except:
                        scanner = SentinelScanner(b'\x00', conf["size"])
                print(f"\n[+] Request received: Switching target to {new_path}")
                try:
                    Processor.run(scanner, new_path, window_size=conf["window"])
                    self.send_response(303)
                    self.send_header('Location', '/')
                    self.end_headers()
                except Exception as e:
                    self.send_error(500, f"Scan failed: {str(e)}")
            else:
                self.send_error(400, "File not found or invalid path")
        else:
            self.send_error(404)

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    def log_message(self, format, *args): return

class ReportGenerator:
    TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelNav</title>
    <style>
        :root {
            --bg-body: #1e1e1e;
            --bg-panel: #252526;
            --bg-header: #2d2d2d;
            --border: #3e3e42;
            --accent: #3794ff;
            --text-main: #cccccc;
            --text-muted: #858585;
            --text-header: #e0e0e0;
            --hex-off: #569cd6;
            --hex-byte: #9cdcfe;
            --hex-ascii: #ce9178;
            --anom-spike: #d16969;
            --anom-drop: #4ec9b0;
            --anom-dense: #c586c0;
        }
        * { box-sizing: border-box; }
        body {
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            font-size: 12px;
        }
        .mono { font-family: 'Consolas', 'Monaco', 'Courier New', monospace; }
        .flex { display: flex; }
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-track { background: var(--bg-body); }
        ::-webkit-scrollbar-thumb { background: #424242; border-radius: 5px; border: 2px solid var(--bg-body); }
        ::-webkit-scrollbar-thumb:hover { background: #4f4f4f; }
        header {
            height: 40px;
            background: var(--bg-header);
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center; padding: 0 16px; justify-content: space-between; z-index: 20;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .brand { font-weight: 600; color: var(--text-header); font-size: 13px; display: flex; align-items: center; gap: 8px; }
        .brand span { color: var(--accent); font-weight: 800; }
        .meta-group { display: flex; gap: 24px; color: var(--text-muted); font-size: 11px; }
        .meta-item b { color: var(--text-header); margin-left: 6px; font-weight: 500; }
        .badge { background: #333; color: #aaa; padding: 2px 8px; border-radius: 12px; font-size: 10px; border: 1px solid #444; }
        .badge.live { background: #203e28; color: #8bd49c; border-color: #2b5636; }
        #workspace { display: flex; flex: 1; overflow: hidden; }
        .control-deck {
            width: 260px;
            background: var(--bg-panel);
            border-right: 1px solid var(--border);
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            overflow-y: auto;
        }
        .widget {
            background: #2d2d2d;
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .widget h4 {
            margin: 0 0 12px 0;
            font-size: 10px;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 600;
            letter-spacing: 0.5px;
            display: flex; justify-content: space-between;
        }
        .stat-row { display: flex; justify-content: space-between; margin-bottom: 6px; color: var(--text-muted); font-size: 11px; }
        .stat-row span:last-child { color: var(--text-main); }
        .btn {
            background: #3e3e42; border: 1px solid transparent; color: #fff; padding: 6px 12px; width: 100%;
            cursor: pointer; border-radius: 2px; transition: all 0.1s; font-size: 11px; font-weight: 500;
        }
        .btn:hover:not(:disabled) { background: #505055; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn.primary { background: var(--accent); color: #fff; }
        .btn.primary:hover { background: #2a7fd9; }
        .btn.anom { background: transparent; border: 1px solid var(--border); color: var(--text-muted); }
        .btn.anom:hover { color: var(--text-main); border-color: #666; }
        .btn.anom.active { background: #3a2d2d; border-color: var(--anom-spike); color: var(--anom-spike); }
        .mode-toggle { display: flex; background: #1e1e1e; padding: 3px; border-radius: 3px; border: 1px solid var(--border); }
        .mode-opt { flex: 1; text-align: center; padding: 4px; cursor: pointer; color: var(--text-muted); font-size: 10px; font-weight: 600; border-radius: 2px; }
        .mode-opt:hover { color: var(--text-main); }
        .mode-opt.active { background: #3e3e42; color: #fff; }
        .spectral-bar { display: flex; height: 6px; margin-top: 8px; width: 100%; border-radius: 3px; overflow: hidden; background: #1e1e1e; }
        .sb-r { background: #e06c75; height: 100%; }
        .sb-g { background: #98c379; height: 100%; }
        .sb-b { background: #61afef; height: 100%; }
        .vis-panel {
            flex: 1;
            background: var(--bg-body);
            position: relative;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background-image: radial-gradient(#2a2a2a 1px, transparent 1px);
            background-size: 20px 20px;
        }
        #canvas-wrap { flex: 1; display: flex; align-items: center; justify-content: center; overflow: hidden; cursor: crosshair; }
        canvas { box-shadow: 0 10px 30px rgba(0,0,0,0.3); image-rendering: pixelated; }
        .legend-list { display: flex; flex-direction: column; gap: 6px; }
        .legend-item { display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--text-muted); }
        .l-dot { width: 8px; height: 8px; border-radius: 50%; }
        .l-box { width: 8px; height: 8px; border-radius: 1px; }
        .inspector-panel { width: 400px; background: var(--bg-panel); border-left: 1px solid var(--border); display: flex; flex-direction: column; }
        .insp-header {
            height: 36px; background: #2d2d2d; border-bottom: 1px solid var(--border);
            display: flex; align-items: center; padding: 0 12px; font-size: 11px; font-weight: 600; color: var(--text-muted);
            justify-content: space-between; letter-spacing: 0.5px;
        }
        .insp-content {
            flex: 1; overflow-y: auto; padding: 12px; font-size: 11px; line-height: 1.5;
            color: var(--hex-byte);
        }
        .search-row { display: flex; gap: 4px; padding: 8px; border-bottom: 1px solid var(--border); background: #202020; }
        .inp-flat { background: #1e1e1e; border: 1px solid var(--border); color: #fff; padding: 4px; font-size: 11px; flex: 1; font-family: monospace; }
        .btn-sm { background: var(--accent); border: none; color: #fff; padding: 0 8px; cursor: pointer; font-size: 10px; }
        .hx-row { display: flex; font-family: 'Consolas', monospace; }
        .hx-off { width: 70px; color: var(--hex-off); user-select: none; }
        .hx-dat { width: 230px; color: var(--hex-byte); margin-right: 12px; }
        .hx-asc { flex: 1; color: var(--hex-ascii); white-space: pre; opacity: 0.8; }
        .b-val { display: inline-block; width: 20px; text-align: center; }
        footer {
            height: 28px; background: var(--accent); color: #fff;
            display: flex; align-items: center; justify-content: flex-end; padding: 0 16px; gap: 15px; font-size: 11px;
            font-weight: 500;
        }
        .pg-btn { background: rgba(0,0,0,0.1); border: none; color: #fff; cursor: pointer; padding: 0 8px; height: 20px; border-radius: 2px; }
        .pg-btn:hover { background: rgba(0,0,0,0.2); }
        .pg-input { background: rgba(0,0,0,0.1); border: none; color: #fff; width: 40px; text-align: center; font-family: monospace; height: 20px; border-radius: 2px; }
        #live-insight {
            border-top: 1px solid var(--border); padding-top: 8px; margin-top: 8px;
            font-style: italic; color: var(--text-main); font-size: 11px; line-height: 1.4;
        }
        #load-area { margin-top: auto; padding: 10px; background: #202020; border-top: 1px solid var(--border); }
        .load-inp { width: 100%; background: #111; border: 1px solid #444; color: #aaa; margin-bottom: 5px; padding: 4px; font-size: 10px; }

        /* NEW: Analysis Box Style */
        .analysis-box {
            padding: 8px 12px;
            background: #202020;
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 11px;
            display: flex; justify-content: space-between; align-items: center;
        }
        .analysis-val { color: var(--accent); font-weight: 600; margin-left:10px; font-family: 'Consolas', monospace; }
    </style>
</head>
<body>

<header>
    <div class="brand"><span>//</span> SENTINEL NAV</div>
    <div class="meta-group">
        <div class="meta-item">TARGET: <b id="fname">...</b></div>
        <div class="meta-item">SIZE: <b id="fsize">0 MB</b></div>
        <div class="meta-item">CHUNKS: <b id="tchunks">0</b></div>
    </div>
    <div id="badge" class="badge">STATIC VIEW</div>
</header>

<div id="workspace">
    <aside class="control-deck">
        <div class="widget">
            <h4>Visualization</h4>
            <div class="mode-toggle">
                <div id="mode-blk" class="mode-opt active" onclick="setMode('block')">BLOCKS</div>
                <div id="mode-px" class="mode-opt" onclick="setMode('pixel')">DENSITY</div>
            </div>
            <button class="btn anom" id="btn-ent" onclick="toggleEntropy()" style="margin-top:10px">Show Entropy Flux</button>
            <button class="btn" id="btn-jump" onclick="jumpToAnomaly()" style="margin-top:5px; font-size:10px; background:transparent; border:1px solid var(--border);">Find Next Flux Event &rarr;</button>
        </div>

        <div class="widget">
            <h4>Export</h4>
            <button class="btn" onclick="downloadBMP()">Export Scan as .BMP</button>
        </div>

        <div class="widget">
            <h4>Live Block Analysis</h4>
            <div id="live-stat-content">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                     <span class="mono" id="live-off" style="color:var(--text-main); font-weight:bold;">HOVER / WASD</span>
                </div>

                <div class="stat-row"><span>Entropy</span> <span id="live-ent" class="mono">0.000</span></div>

                <div style="margin-top:12px; margin-bottom:4px; font-size:9px; color:var(--text-muted); font-weight:600; letter-spacing:0.5px;">BYTE CLASS SPECTRAL</div>
                <div class="spectral-bar">
                    <div id="live-r" class="sb-r" style="width:0%"></div>
                    <div id="live-g" class="sb-g" style="width:0%"></div>
                    <div id="live-b" class="sb-b" style="width:0%"></div>
                </div>
                <div style="display:flex; justify-content:space-between; font-size:9px; color:var(--text-muted); margin-top:4px;">
                    <span>HI-BIT</span><span>TXT</span><span>NULL</span>
                </div>

                <div id="live-insight">
                    Use mouse or keyboard to inspect blocks.
                </div>
            </div>
        </div>

        <div class="widget">
            <h4>Spectral Legend</h4>
            <div class="legend-list">
                <div class="legend-item"><div class="l-dot" style="background:#e06c75"></div> High Bit (Media/Crypto)</div>
                <div class="legend-item"><div class="l-dot" style="background:#98c379"></div> Printable (Text/Src)</div>
                <div class="legend-item"><div class="l-dot" style="background:#61afef"></div> Control (Null/Pad)</div>
                <div style="height:1px; background:var(--border); margin:4px 0;"></div>
                <div class="legend-item"><div class="l-box" style="border:1px solid var(--anom-spike)"></div> Entropy Spike</div>
                <div class="legend-item"><div class="l-box" style="border:1px solid var(--anom-drop)"></div> Entropy Drop</div>
            </div>
        </div>

        <div class="widget">
            <h4>Selection</h4>
            <div class="stat-row"><span>Status</span> <span id="sel-stat">Idle</span></div>
            <div class="stat-row"><span>Start</span> <span id="sel-off" class="mono">-</span></div>
            <div class="stat-row"><span>Size</span> <span id="sel-len" class="mono">-</span></div>
            <hr style="border:0; border-top:1px solid var(--border); margin:10px 0;">
             <div class="stat-row"><span>Actions</span></div>
            <div style="display:flex; gap:6px; margin-top:5px;">
                <button class="btn" id="btn-dl" disabled>Dump .BIN</button>
                <button class="btn primary" id="btn-rep" disabled>Report</button>
            </div>
        </div>

        <div id="load-area">
            <h4 style="margin:0 0 5px 0; color:#888; font-size:9px;">CHANGE TARGET FILE</h4>
            <form action="/load" method="POST">
                <input type="text" name="filepath" class="load-inp" placeholder="/path/to/file">
                <button type="submit" class="btn" style="font-size:9px;">LOAD & RESCAN</button>
            </form>
        </div>

        <div style="margin-top:auto; font-size:10px; color:var(--text-muted); text-align:center;">
            <span class="mono">W A S D</span> to Navigate
        </div>
    </aside>

    <main class="vis-panel">
        <div id="canvas-wrap"><canvas id="cvs"></canvas></div>
    </main>

    <aside class="inspector-panel">
        <div class="insp-header">
            <span>HEX INSPECTOR</span>
        </div>
        <div class="search-row">
            <input type="text" id="hex-search" class="inp-flat" placeholder="Find Hex (e.g. 4D 5A 90)">
            <button class="btn-sm" onclick="runSearch()">FIND</button>
        </div>
        <!-- NEW FEATURE: ArchID Display -->
        <div class="analysis-box">
             <span>Deep Analysis:</span>
             <span id="insp-arch-val" class="analysis-val">--</span>
        </div>

        <div id="inspector" class="insp-content mono">
            <div style="color:var(--text-muted); text-align:center; padding-top:60px;">
                Select a chunk to inspect data.<br>
                <span style="font-size:24px; display:block; margin-top:16px; opacity:0.3;">&#8982;</span>
            </div>
        </div>
    </aside>
</div>

<footer>
    <span style="margin-right:auto; padding-left:16px; font-size:10px; opacity:0.8;">MODE: <span id="cfg-mode">__MODE_NAME__</span></span>

    <button class="pg-btn" id="btn-prev" onclick="changePage(-1)">&larr;</button>
    <span class="mono" id="pg-display" style="min-width:80px; text-align:center;">Page 1 / 1</span>
    <button class="pg-btn" id="btn-next" onclick="changePage(1)">&rarr;</button>
    <span style="opacity:0.5">|</span>
    <span>Go to:</span>
    <input type="number" id="pg-jump" class="pg-input" min="1" onchange="jumpToPage(this.value)">
</footer>

<script>
    const IS_LIVE = window.location.protocol.startsWith('http');
    const FILENAME = "__FILENAME__";
    const FILESIZE = __FILESIZE__;
    let TOTAL_CHUNKS = __TOTAL_CHUNKS__;
    let CHUNKS = __DATA_JSON__;
    let ANOM = __ANOM_JSON__;

    let PAGE_SIZE = 10000;
    let CURR_PAGE = 0;
    let TOTAL_PAGES = Math.ceil(TOTAL_CHUNKS / PAGE_SIZE);
    let RENDER_MODE = 'block';
    let CELL_SIZE = 8;
    let GAP = 1;
    let ENTROPY_HIGHLIGHT = false;

    let anchorIdx = -1; let cursorIdx = -1; let selStartIdx = -1; let selEndIdx = -1;

    const cvs = document.getElementById('cvs');
    const ctx = cvs.getContext('2d', {alpha:false});
    const wrapper = document.getElementById('canvas-wrap');
    const inspContainer = document.getElementById('inspector');

    function init() {
        document.getElementById('fname').innerText = FILENAME.length > 20 ? FILENAME.substr(0,20)+'...' : FILENAME;
        document.getElementById('fsize').innerText = (FILESIZE/1024/1024).toFixed(2) + " MB";
        document.getElementById('tchunks').innerText = TOTAL_CHUNKS.toLocaleString();
        if(IS_LIVE) {
            let b = document.getElementById('badge');
            b.classList.add('live');
            b.innerText = "LIVE SERVER";
            fetchPage(0);
        } else {
            TOTAL_PAGES = 1; updateUI(); resizeAndRender();
        }
        setMode('block');
    }

    function downloadBMP() {
        if(!IS_LIVE) return alert("BMP export requires live server.");
        window.location.href = "/download?mode=bmp";
    }

    function runSearch() {
        let val = document.getElementById('hex-search').value;
        if(!val) return;
        fetch(`/search?hex=${encodeURIComponent(val)}`)
            .then(r => r.json())
            .then(d => {
                if(d.found) {
                   alert("Found at Offset 0x" + d.offset.toString(16).toUpperCase());
                   for(let i=0; i<CHUNKS.length; i++) {
                       if(d.offset >= CHUNKS[i][0] && d.offset < (CHUNKS[i][0] + CHUNKS[i][1])) {
                           cursorIdx = i; anchorIdx = i; selStartIdx = i; selEndIdx = i;
                           updateSelectionInfo(); resizeAndRender(); updateLiveStats(i);
                           return;
                       }
                   }
                   alert("Found, but offset is on a different page. Please navigate.");
                } else {
                    alert("Hex sequence not found.");
                }
            });
    }

    function setMode(m) {
        RENDER_MODE = m;
        document.getElementById('mode-blk').className = m=='block'?'mode-opt active':'mode-opt';
        document.getElementById('mode-px').className = m=='pixel'?'mode-opt active':'mode-opt';
        if(m === 'block') { CELL_SIZE = 10; GAP = 1; } else { CELL_SIZE = 2; GAP = 0; }
        resizeAndRender();
    }

    function toggleEntropy() {
        ENTROPY_HIGHLIGHT = !ENTROPY_HIGHLIGHT;
        let b = document.getElementById('btn-ent');
        b.className = ENTROPY_HIGHLIGHT ? "btn anom active" : "btn anom";
        b.innerText = ENTROPY_HIGHLIGHT ? "Entropy Flux: ON" : "Entropy Flux: OFF";
        resizeAndRender();
    }

    function jumpToAnomaly() {
        let start = cursorIdx + 1;
        if(start >= CHUNKS.length) start = 0;
        for(let i=start; i<CHUNKS.length; i++) {
            if(ANOM[i][0] > 0.6) {
                cursorIdx = i; anchorIdx = i; selStartIdx = i; selEndIdx = i;
                updateSelectionInfo(); resizeAndRender();
                updateLiveStats(i);
                return;
            }
        }
        alert("No more flux events found on this page.");
    }

    function changePage(delta) {
        let next = CURR_PAGE + delta;
        if(next >= 0 && next < TOTAL_PAGES) fetchPage(next);
    }
    function jumpToPage(val) {
        let p = parseInt(val) - 1;
        if(p >= 0 && p < TOTAL_PAGES) fetchPage(p);
        else document.getElementById('pg-jump').value = CURR_PAGE + 1;
    }
    function fetchPage(pNum) {
        if(!IS_LIVE) return;
        document.getElementById('pg-display').innerText = "Loading...";
        fetch(`/data?page=${pNum}&size=${PAGE_SIZE}`).then(r=>r.json()).then(d => {
            CHUNKS = d.chunks; ANOM = d.anom; TOTAL_CHUNKS = d.total;
            TOTAL_PAGES = Math.ceil(TOTAL_CHUNKS / PAGE_SIZE);
            CURR_PAGE = pNum;
            selStartIdx = -1; selEndIdx = -1; anchorIdx = -1; cursorIdx = -1;
            updateUI(); resizeAndRender();
        });
    }

    function updateUI() {
        document.getElementById('pg-display').innerText = `Page ${CURR_PAGE+1} / ${TOTAL_PAGES}`;
        let inp = document.getElementById('pg-jump'); inp.value = CURR_PAGE + 1; inp.max = TOTAL_PAGES;
        document.getElementById('tchunks').innerText = TOTAL_CHUNKS.toLocaleString();
        document.getElementById('btn-prev').disabled = (CURR_PAGE === 0);
        document.getElementById('btn-next').disabled = (CURR_PAGE === TOTAL_PAGES - 1);
    }

    function resizeAndRender() {
        let availW = wrapper.clientWidth - 20;
        let u = CELL_SIZE + GAP;
        let cols = Math.floor(availW / u); if(cols < 1) cols = 1;
        let rows = Math.ceil(CHUNKS.length / cols);
        cvs.width = cols * u; cvs.height = rows * u;

        ctx.fillStyle = "#1e1e1e";
        ctx.fillRect(0,0,cvs.width,cvs.height);

        for(let i=0; i<CHUNKS.length; i++) {
            let x = (i % cols) * u;
            let y = Math.floor(i / cols) * u;
            let ent = CHUNKS[i][2];
            let rPerc = CHUNKS[i][3];
            let gPerc = CHUNKS[i][4];
            let bPerc = CHUNKS[i][5];
            let fluxType = ANOM[i][1];
            let r = Math.min(255, Math.floor(rPerc * 255));
            let g = Math.min(255, Math.floor(gPerc * 255));
            let b = Math.min(255, Math.floor(bPerc * 255));

            if(rPerc > 0.8) ctx.fillStyle = `rgb(${224}, ${108}, ${117})`;
            else if(gPerc > 0.8) ctx.fillStyle = `rgb(${152}, ${195}, ${121})`;
            else if(bPerc > 0.8) ctx.fillStyle = `rgb(${97}, ${175}, ${239})`;
            else ctx.fillStyle = `rgb(${r},${g},${b})`;

            ctx.fillRect(x,y,CELL_SIZE,CELL_SIZE);

            if (ENTROPY_HIGHLIGHT) {
                if(fluxType > 0) {
                     ctx.lineWidth = 2;
                     if (fluxType === 1) ctx.strokeStyle = "#d16969";
                     else if (fluxType === 2) ctx.strokeStyle = "#4ec9b0";
                     else if (fluxType === 3) ctx.strokeStyle = "#c586c0";
                     ctx.strokeRect(x,y,CELL_SIZE,CELL_SIZE);
                } else {
                     ctx.fillStyle = "rgba(30,30,30,0.7)";
                     ctx.fillRect(x,y,CELL_SIZE,CELL_SIZE);
                }
            }
            if (selStartIdx !== -1 && i >= selStartIdx && i <= selEndIdx) {
                ctx.fillStyle = "rgba(255,255,255,0.4)"; ctx.fillRect(x,y,CELL_SIZE,CELL_SIZE);
            }
            if(i === cursorIdx) {
                ctx.strokeStyle = "#fff"; ctx.lineWidth = 1; ctx.strokeRect(x-1,y-1,CELL_SIZE+2,CELL_SIZE+2);
            }
        }
    }

    window.addEventListener('keydown', e => {
        if(e.target.tagName === 'INPUT') return;
        let availW = wrapper.clientWidth - 20;
        let cols = Math.floor(availW / (CELL_SIZE + GAP)); if(cols < 1) cols = 1;

        if (['w','a','s','d'].includes(e.key.toLowerCase())) {
            let nextIdx = cursorIdx;
            if (cursorIdx === -1 && CHUNKS.length > 0) nextIdx = 0;
            else {
                if(e.key.toLowerCase() === 'a') nextIdx -= 1;
                if(e.key.toLowerCase() === 'd') nextIdx += 1;
                if(e.key.toLowerCase() === 'w') nextIdx -= cols;
                if(e.key.toLowerCase() === 's') nextIdx += cols;
            }
            if(nextIdx < 0) nextIdx = 0;
            if(nextIdx >= CHUNKS.length) nextIdx = CHUNKS.length - 1;

            if(nextIdx !== cursorIdx) {
                cursorIdx = nextIdx;
                if(e.shiftKey) {
                    if(anchorIdx === -1) anchorIdx = cursorIdx;
                    selStartIdx = Math.min(anchorIdx, cursorIdx);
                    selEndIdx = Math.max(anchorIdx, cursorIdx);
                } else {
                    anchorIdx = cursorIdx; selStartIdx = cursorIdx; selEndIdx = cursorIdx;
                }
                updateSelectionInfo(); resizeAndRender();
                updateLiveStats(cursorIdx);
            }
        }
        else if (e.key === "ArrowLeft") changePage(-1);
        else if (e.key === "ArrowRight") changePage(1);
    });

    function getIdx(e) {
        let r = cvs.getBoundingClientRect();
        let u = CELL_SIZE + GAP;
        let c = Math.floor((e.clientX - r.left)/u);
        let row = Math.floor((e.clientY - r.top)/u);
        let cols = Math.floor(cvs.width/u);
        return (row * cols) + c;
    }

    cvs.addEventListener('mousemove', e => {
        let i = getIdx(e);
        if(i >= 0 && i < CHUNKS.length) {
            updateLiveStats(i);
        }
    });

    function updateLiveStats(i) {
        let c = CHUNKS[i];
        let fluxType = ANOM[i][1];
        let insight = "";
        let ent = c[2];
        let r = c[3]; let g = c[4]; let b = c[5];

        if(fluxType === 1) insight = "<span style='color:var(--anom-spike)'>⚠️ Sudden Entropy Spike (Start of Code/Crypto?)</span>";
        else if(fluxType === 2) insight = "<span style='color:var(--anom-drop)'>⚠️ Sudden Entropy Drop (End of Stream?)</span>";
        else if(fluxType === 3) insight = "<span style='color:var(--anom-dense)'>⚠️ Sustained High Density (Packed/Encrypted)</span>";
        else {
            if(ent < 0.1) insight = "Zero Region: Mostly null bytes. Likely padding.";
            else if(ent < 3.0 && g > 0.8) insight = "Plaintext: High ASCII density. Logs, JSON, or Source.";
            else if(ent > 7.85) insight = "High Noise: Indistinguishable from random data (Crypto/Comp).";
            else if(r > 0.6) insight = "Binary Density: Heavy high-bit usage. Machine code or Media.";
            else if(b > 0.5) insight = "Sparse Data: High control char count. Metadata/Headers.";
            else insight = "Structured Binary: Mixed content (Executables/Headers).";
        }

        document.getElementById('live-off').innerText = "0x" + c[0].toString(16).toUpperCase();
        document.getElementById('live-ent').innerText = ent.toFixed(3);
        document.getElementById('live-r').style.width = Math.floor(r*100) + "%";
        document.getElementById('live-g').style.width = Math.floor(g*100) + "%";
        document.getElementById('live-b').style.width = Math.floor(b*100) + "%";
        document.getElementById('live-insight').innerHTML = insight;
    }

    cvs.addEventListener('click', e => {
        let i = getIdx(e);
        if(i >= 0 && i < CHUNKS.length) {
            cursorIdx = i;
            if(e.shiftKey && anchorIdx !== -1) {
                selStartIdx = Math.min(anchorIdx, i); selEndIdx = Math.max(anchorIdx, i);
            } else {
                anchorIdx = i; selStartIdx = i; selEndIdx = i;
            }
            updateSelectionInfo(); resizeAndRender();
        }
    });

    function updateSelectionInfo() {
        if(selStartIdx === -1) return;
        let startChunk = CHUNKS[selStartIdx];
        let endChunk = CHUNKS[selEndIdx];
        let startOff = startChunk[0];
        let totalLen = (endChunk[0] + endChunk[1]) - startOff;

        document.getElementById('sel-stat').innerText = (selEndIdx - selStartIdx) + 1 + " Blocks";
        document.getElementById('sel-off').innerText = "0x"+startOff.toString(16).toUpperCase();
        document.getElementById('sel-len').innerText = totalLen > 1024 ? (totalLen/1024).toFixed(2)+" KB" : totalLen+" B";

        let btnDl = document.getElementById('btn-dl'); let btnRep = document.getElementById('btn-rep');
        btnDl.disabled = false; btnRep.disabled = false;

        let nDl = btnDl.cloneNode(true); btnDl.parentNode.replaceChild(nDl, btnDl);
        let nRep = btnRep.cloneNode(true); btnRep.parentNode.replaceChild(nRep, btnRep);

        nDl.addEventListener('click', ()=> window.location.href=`/download?offset=${startOff}&length=${totalLen}&mode=bin`);
        nRep.addEventListener('click', ()=> window.location.href=`/download?offset=${startOff}&length=${totalLen}&mode=txt`);

        let c = CHUNKS[cursorIdx];
        inspect(c[0], c[1]);
    }

    function inspect(off, len) {
        let insp = document.getElementById('inspector');
        let archDisplay = document.getElementById('insp-arch-val');

        if(!IS_LIVE) return insp.innerHTML = "<div style='padding:20px; text-align:center; color:var(--text-muted)'>Static mode.</div>";

        insp.innerHTML = "<div style='padding:20px; text-align:center; color:var(--accent)'>Fetching binary stream...</div>";
        archDisplay.innerText = "Analyzing...";

        fetch(`/read?offset=${off}&length=${len}`).then(r=>r.json()).then(d=>{
            // FEATURE: DISPLAY ARCH ID
            archDisplay.innerText = d.arch || "Unknown";

            let hex = d.hex; let html = "";
            for(let i=0; i<hex.length; i+=32) {
                let chunk = hex.substr(i, 32);
                let rowOffVal = off + i/2;
                let rowOff = rowOffVal.toString(16).toUpperCase().padStart(8,'0');
                let asc = ""; let h = "";
                for(let j=0; j<chunk.length; j+=2) {
                    let bVal = parseInt(chunk.substr(j,2), 16);
                    let bHex = chunk.substr(j,2);
                    h += `<span class='b-val'>${bHex}</span> `;
                    asc += (bVal>=32&&bVal<=126) ? String.fromCharCode(bVal) : ".";
                }
                html += `<div class="hx-row"><div class="hx-off">${rowOff}</div><div class="hx-dat">${h}</div><div class="hx-asc">${asc.replace(/</g,'&lt;')}</div></div>`;
            }
            insp.innerHTML = html;
        });
    }

    window.addEventListener('resize', resizeAndRender);
    init();
</script>

</body>
</html>
    """
    @staticmethod
    def get_html(filename, config_name, is_server):
        limit = 50000
        if not ENGINE:
            return "<html><body><h1>Engine Reloading...</h1></body></html>"
        chunks, anoms = ENGINE.get_page(0, limit)
        total = ENGINE.get_total_count()
        json_c = json.dumps(chunks)
        json_a = json.dumps(anoms)
        fsize = os.path.getsize(filename) if os.path.exists(filename) else 0
        h = ReportGenerator.TEMPLATE
        h = h.replace("__FILENAME__", os.path.basename(filename).replace("\\","\\\\"))
        h = h.replace("__FILESIZE__", str(fsize))
        h = h.replace("__TOTAL_CHUNKS__", str(total))
        h = h.replace("__DATA_JSON__", json_c)
        h = h.replace("__ANOM_JSON__", json_a)
        h = h.replace("__MODE_NAME__", config_name)
        return h

# --- 5. INTERACTIVE CLI WIZARD ---

def print_cheat_sheet():
    print("""
░█▀▀░█▀▀░█▀█░▀█▀░▀█▀░█▀█░█▀▀░█░░
░▀▀█░█▀▀░█░█░░█░░░█░░█░█░█▀▀░█░░
░▀▀▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀
>>> NAVIGATOR <<<

╔════ CHEAT SHEET & CONFIG GUIDE ═════════════════════════════════════════╗
║                                                                         ║
║  SPECTRAL MAPPING:                                                      ║
║    RED (High Bit): Media, Crypto, Compiled Code.                        ║
║    GREEN (Printable): Text, Strings, Source Code.                       ║
║    BLUE (Control): Zero Padding, Nulls, Headers.                        ║
║                                                                         ║
║  SCAN TYPES:                                                            ║
║    [1] FIXED:     Slices file into equal blocks. Best for binary/img.   ║
║    [2] SENTINEL:  Slices on delimiter (e.g. 0x0A for newlines).         ║
║                                                                         ║
║  CONTROLS: WASD for keyboard chunk navigation, Arrow Key for page,      ║
║    and hold shift and click left mouse button or WASD to select chunk   ║
║                              for download.                              ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
""")
def interactive_wizard():
    print_cheat_sheet()
    target = ""
    while not target:
        raw = input(" [?] Drag & Drop file here: ").strip()
        target = raw.strip("'").strip('"')
        if not os.path.exists(target):
            print(" [!] File not found.")
            target = ""
    print(f"\n [+] Target: {os.path.basename(target)}")
    print("\n [?] Select Scan Mode:")
    print("     [1] FIXED BLOCK (Standard)")
    print("     [2] SENTINEL (Search for delimiters)")
    mode_in = input("     Selection [1]: ").strip()
    mode = "SENTINEL" if mode_in == "2" else "FIXED"
    default_size = 1024
    print(f"\n [?] Block Size (Bytes):")
    print(f"     Default is {default_size} (Balanced). 256 for HD.")
    size_in = input(f"     Size [{default_size}]: ").strip()
    try:
        size = int(size_in) if size_in else default_size
    except ValueError:
        size = default_size
    if size < 256:
        print("\n [!] WARNING: You selected a very small chunk size (< 256 bytes).")
        print("     This creates massive overhead (SQL/IPC) for large files.")
        confirm = input("     Are you sure? (y/N): ").lower()
        if confirm != 'y':
            print(f"     > Resetting to safe default: {default_size}")
            size = default_size
    hex_val = "00"
    if mode == "SENTINEL":
        h = input("\n [?] Delimiter Byte Hex (e.g. 0A for line break, 00 for null) [00]: ").strip()
        hex_val = h if h else "00"
    conf = {
        "mode": mode,
        "size": size,
        "hex": hex_val,
        "port": 8000,
        "window": 5,
        "name": f"Custom ({mode} {size}B)"
    }
    return target, conf

def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument("target", help="File to scan")
        parser.add_argument("--mode", choices=["fixed", "sentinel"], default="fixed")
        parser.add_argument("--size", type=int, default=1024, help="Block size or Max buffer. Default 1024.")
        parser.add_argument("--hex", default="00", help="Delimiter byte (Sentinel mode)")
        parser.add_argument("--port", type=int, default=8000, help="Web server port")
        parser.add_argument("--window", type=int, default=5, help="Anomaly detection window size")
        args = parser.parse_args()
        safe_size = args.size
        if safe_size < 256:
            print("[!] Warning: --size < 256 detected. This may cause system instability on large files.")
        target = args.target
        conf = {
            "mode": args.mode.upper(),
            "size": safe_size,
            "hex": args.hex,
            "port": args.port,
            "window": args.window,
            "name": f"CLI ({args.mode.upper()} {safe_size})"
        }
    else:
        target, conf = interactive_wizard()

    print(f"\n[+] Initializing scan on {os.path.basename(target)}...")
    print(f"    Config: {conf['mode']} | Size: {conf['size']} bytes | Port: {conf['port']}")

    scanner = None
    if conf["mode"] == "FIXED":
        scanner = FixedScanner(conf["size"])
    else:
        try:
            hx = conf.get("hex", "00")
            scanner = SentinelScanner(bytes.fromhex(hx), conf["size"])
        except:
            print("[!] Invalid Hex. Defaulting to 0x00.")
            scanner = SentinelScanner(b'\x00', conf["size"])

    global SERVER_FILE_PATH, SERVER_CONFIG
    SERVER_FILE_PATH = target
    SERVER_CONFIG = conf

    try:
        Processor.run(scanner, target, window_size=conf["window"])
    except KeyboardInterrupt:
        print("\n[!] Cancelled.")
        if ENGINE: ENGINE.close()
        return

    print(f"\n[+] SERVER READY: http://localhost:{conf['port']}")
    print("[+] Press CTRL+C to stop.")

    try:
        with ThreadedHTTPServer(("127.0.0.1", conf['port']), ByteServer) as httpd:
            httpd.serve_forever()
    except OSError:
        print(f"[!] Error: Port {conf['port']} is in use.")
    except KeyboardInterrupt:
        print("\n[+] Exiting.")
    finally:
        if ENGINE: ENGINE.close()

if __name__ == "__main__":
    main()

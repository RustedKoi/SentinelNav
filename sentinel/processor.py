import os
import sys
import concurrent.futures
from collections import Counter
from .core import FastMath

def _worker_scan(args):
    """Must be top-level for multiprocessing pickle support"""
    offset, data = args
    if not data: return (offset, 0, 0.0, 0.0, 0.0, 0.0)
    length = len(data)
    ent = FastMath.entropy(data)
    counts = Counter(data)
    r = sum(c for b,c in counts.items() if 0x80 <= b <= 0xFF)
    g = sum(c for b,c in counts.items() if 0x20 <= b <= 0x7E)
    b = sum(c for b,c in counts.items() if 0x00 <= b <= 0x1F)
    return (offset, length, round(ent, 3), round(r/length, 3), round(g/length, 3), round(b/length, 3))

class Processor:
    @staticmethod
    def run(scanner, target_file, db_engine, window_size=5):
        file_size = os.path.getsize(target_file)
        workers = max(1, (os.cpu_count() or 1) - 1)
        print(f"[+] Scanning {file_size/1024/1024:.2f} MB using {workers} workers...")

        hist_ent = []
        batch = []
        count = 0
        prev_ent = 0.0

        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
            chunk_gen = scanner.yield_raw_chunks(target_file)
            for res in executor.map(_worker_scan, chunk_gen, chunksize=20):
                offset, length, ent, r, g, b = res
                
                # Anomaly Detection Logic
                anom_score, flux_type = 0.0, 0
                if len(hist_ent) >= window_size:
                    diff = abs(ent - (sum(hist_ent) / len(hist_ent)))
                    anom_score = min(1.0, diff / 2.0)
                
                delta = ent - prev_ent
                if delta > 1.5 and ent > 6.0: flux_type, anom_score = 1, anom_score + 0.8
                elif delta < -1.5 and ent < 3.0: flux_type, anom_score = 2, anom_score + 0.8
                elif ent > 7.95: flux_type, anom_score = 3, anom_score + 0.5

                prev_ent = ent
                hist_ent.append(ent)
                if len(hist_ent) > window_size * 2: hist_ent.pop(0)

                batch.append((offset, length, ent, r, g, b, anom_score, flux_type))
                count += 1
                if len(batch) >= 2000:
                    db_engine.insert_bulk(batch)
                    batch = []
                    sys.stdout.write(f"\r    Processed {count} blocks...")
                    sys.stdout.flush()

        if batch: db_engine.insert_bulk(batch)
        print(f"\n[+] Scan complete. Total blocks: {count}")

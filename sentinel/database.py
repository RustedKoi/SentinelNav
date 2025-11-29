import sqlite3
import tempfile
import os

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
                offset INTEGER, length INTEGER, entropy REAL,
                r_val REAL, g_val REAL, b_val REAL,
                anom_score REAL, flux_type INTEGER
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
        return [(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rows], [(round(r[6], 2), r[7]) for r in rows]

    def get_all_spectral_data(self):
        self.cursor.execute("SELECT r_val, g_val, b_val FROM chunks ORDER BY id ASC")
        return self.cursor.fetchall()

    def get_total_count(self):
        self.cursor.execute("SELECT COUNT(*) FROM chunks")
        res = self.cursor.fetchone()
        return res[0] if res else 0

    def close(self):
        self.conn.close()
        try: os.unlink(self.db_path)
        except: pass

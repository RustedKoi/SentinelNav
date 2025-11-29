import os
import json

class ReportGenerator:
    # Use the HTML template from your original code here
    TEMPLATE = """<!DOCTYPE html>... (Paste original HTML here) ...</html>"""
    
    @staticmethod
    def get_html(filename, config_name, db_engine):
        if not db_engine: return "<h1>Engine Offline</h1>"
        chunks, anoms = db_engine.get_page(0, 50000)
        fsize = os.path.getsize(filename) if os.path.exists(filename) else 0
        
        # Simple string replacement
        h = ReportGenerator.TEMPLATE
        h = h.replace("__FILENAME__", os.path.basename(filename).replace("\\","\\\\"))
        h = h.replace("__FILESIZE__", str(fsize))
        h = h.replace("__TOTAL_CHUNKS__", str(db_engine.get_total_count()))
        h = h.replace("__DATA_JSON__", json.dumps(chunks))
        h = h.replace("__ANOM_JSON__", json.dumps(anoms))
        h = h.replace("__MODE_NAME__", config_name)
        return h

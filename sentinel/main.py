import sys
import os
import argparse
import webbrowser
from .database import DataEngine
from .scanners import FixedScanner, SentinelScanner
from .processor import Processor
from .server import ThreadedHTTPServer, ByteServer, ServerContext

def interactive_wizard():
    target = ""
    while not target:
        raw = input(" [?] Drag & Drop file: ").strip().strip("'\"")
        if os.path.exists(raw): target = raw
    
    print("\n [?] Mode: [1] Fixed Block (Default)  [2] Sentinel")
    mode = "SENTINEL" if input("     Choice: ") == "2" else "FIXED"
    
    size = input(" [?] Block Size [1024]: ").strip()
    size = int(size) if size else 1024
    
    return target, {"mode": mode, "size": size, "port": 8000, "window": 5, "name": f"Wizard {mode}"}

def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument("target")
        parser.add_argument("--mode", default="fixed")
        parser.add_argument("--size", type=int, default=1024)
        parser.add_argument("--port", type=int, default=8000)
        args = parser.parse_args()
        target = args.target
        conf = {"mode": args.mode.upper(), "size": args.size, "port": args.port, "window": 5, "name": "CLI"}
    else:
        target, conf = interactive_wizard()

    # 1. Initialize DB
    engine = DataEngine()
    
    # 2. Configure Scanner
    if conf["mode"] == "FIXED":
        scanner = FixedScanner(conf["size"])
    else:
        scanner = SentinelScanner(b'\x00', conf["size"])

    # 3. Process File
    try:
        Processor.run(scanner, target, engine, conf["window"])
    except KeyboardInterrupt:
        engine.close()
        return

    # 4. Start Server
    ServerContext.file_path = target
    ServerContext.config = conf
    ServerContext.engine = engine
    
    print(f"\n[+] SERVER: http://localhost:{conf['port']}")
    try:
        with ThreadedHTTPServer(("127.0.0.1", conf['port']), ByteServer) as httpd:
            webbrowser.open(f"http://127.0.0.1:{conf['port']}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Exiting.")
    finally:
        engine.close()

if __name__ == "__main__":
    main()

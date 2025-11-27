# SentinelNav

SentinelNav is a zero-dependency, pure Python binary visualization and forensics tool. It transforms binary data into an interactive spectral map, allowing analysts to visually identify file structures, entropy anomalies, code sections, and potential cryptographic blobs.

It combines a multiprocessing backend for fast file scanning with a local web-based frontend for interactive exploration, hex inspection, and architecture fingerprinting.

[https://imgur.com/a/N96qgXI]

[https://imgur.com/TkB0zLO]

---

## Quickstart

Since SentinelNav relies only on the Python Standard Library, no installation of external packages is required.

1.  Save the script as `sentinelnav.py`.
2.  Run the script in interactive mode:

```bash
python3 sentinelnav.py
```

3.  Drag and drop a target file into the terminal window when prompted.
4.  Open your browser to `http://localhost:8000`.

---

---

## Features

### Core Analysis

- **Zero-Dependency:** Runs on any standard Python 3 installation without `pip install`.
- **Hybrid Scanning Modes:**
  - **Fixed Block:** Slices files into consistent chunks (e.g., 1024 bytes). Ideal for binaries and disk images.
  - **Sentinel:** Slices files based on a delimiter (e.g., `0x0A` for logs or text-based protocols).
- **Architecture Fingerprinting (ArchID):**
  - Detects file headers (MZ, ELF, Mach-O, PDF, PNG, JPEG).
  - Performs heuristic frequency analysis to guess CPU architecture (x86, x64, ARM64) on raw binary chunks.
- **Entropy & Anomaly Detection:**
  - Calculates Shannon entropy per block.
  - Detects "Flux" events: Sudden spikes (start of encryption/code) or drops (end of data streams).

### Visualization

- **Spectral Mapping:** Maps byte distribution to RGB colors to visually distinguish data types (Text vs. Code vs. Padding).
- **Canvas Rendering:** High-performance HTML5 canvas rendering capable of handling millions of chunks via pagination.
- **Live Hex Inspector:** Click any block to view the raw hex dump, ASCII decoding, and ArchID analysis.
- **BMP Export:** Generate a full heatmap image of the file for external reporting.

### Performance

- **Parallel Processing:** Uses `concurrent.futures.ProcessPoolExecutor` to utilize all CPU cores during scanning.
- **SQLite Backend:** Stores analysis results in a temporary SQLite database to allow efficient pagination and querying of large files (GB+).

---

## Architecture Design

SentinelNav follows a Producer-Consumer architecture with a Client-Server interface.

### 1. The Forensics Engine (Backend)

- **Scanner Interface:**
  - Abstracts the file reading process.
  - **FixedScanner:** Reads `N` bytes iteratively.
  - **SentinelScanner:** Reads into a buffer and yields chunks upon finding specific bytes (e.g., null bytes or newlines).
- **Worker Process:**
  - The `Processor` spawns a pool of workers based on CPU count.
  - **FastMath:** Computes entropy and byte frequency counts (Spectral Data).
  - **Heuristics:** Determines if a chunk is ASCII-heavy, Null-heavy, or High-Bit heavy.
- **Data Engine (Storage):**
  - An ephemeral `sqlite3` database creates a structured index of the binary file.
  - Stores: Offset, Length, Entropy, RGB values, Anomaly Scores.
  - This allows the tool to handle files larger than available RAM by paging data on demand.

### 2. The Web Server

- Implements `http.server.ThreadingMixIn` for concurrent handling of HTTP requests.
- **API Endpoints:**
  - `/data`: Returns JSON pages of chunk data (Color + Entropy).
  - `/read`: specific hex dumps for the Inspector panel.
  - `/search`: Scans the physical file for hex sequences.
  - `/download`: Extracts raw binary blobs or generates the BMP visualization.

### 3. The Frontend

- Single-Page Application (SPA) embedded directly in the Python script.
- **Rendering:** Uses HTML5 Canvas API for pixel-perfect block rendering.
- **Navigation:** Implements spatial navigation logic to map keyboard inputs (WASD) to the grid coordinate system.

---

## Visual Mapping Guide

The tool uses a specific RGB algorithm to represent binary data types.

| Color     | Component | Meaning                                                                                                  |
| :-------- | :-------- | :------------------------------------------------------------------------------------------------------- |
| **RED**   | High Bit  | Bytes `0x80` - `0xFF`. Indicates compiled machine code, compressed data, encrypted blobs, or image data. |
| **GREEN** | ASCII     | Bytes `0x20` - `0x7E`. Indicates plain text, source code, JSON, XML, or logs.                            |
| **BLUE**  | Control   | Bytes `0x00` - `0x1F`. Indicates null padding, headers, or protocol control characters.                  |

**Common Patterns:**

- **Bright Green:** Text file or source code.
- **Pink/Purple:** Mixed code and data (Executable sections).
- **Solid Blue:** Zero-filled padding or empty space.
- **Static/Grey:** High entropy noise (Encrypted data).

---

## Installation

### Prerequisites

- Python 3.6 or higher.

### Setup

No libraries need to be installed. Simply download the file.

```bash
# Clone or download the script
wget https://raw.githubusercontent.com/user/repo/main/sentinelnav.py
```

---

## Usage & CLI Arguments

You can run the tool interactively or via command-line arguments.

### Interactive Wizard

Running without arguments launches the wizard:

```bash
python3 sentinelnav.py
```

### CLI Arguments

For automation or power users, use flags to skip the wizard.

```bash
python3 sentinelnav.py <target_file> [options]
```

| Argument   | Description                                                       | Default |
| :--------- | :---------------------------------------------------------------- | :------ |
| `--mode`   | Scan mode: `fixed` or `sentinel`.                                 | `fixed` |
| `--size`   | Block size (in bytes) for fixed mode, or max buffer for sentinel. | `1024`  |
| `--hex`    | The delimiter byte for sentinel mode (e.g., `0A` for newline).    | `00`    |
| `--port`   | The web server port.                                              | `8000`  |
| `--window` | Sliding window size for anomaly detection calculations.           | `5`     |

**Example:**
Scan a firmware image with a 256-byte resolution on port 8080:

```bash
python3 sentinelnav.py firmware.bin --size 256 --port 8080
```

---

## Keyboard Controls

Once the web interface is loaded, the following controls are available:

| Key               | Action                                                        |
| :---------------- | :------------------------------------------------------------ |
| **W / A / S / D** | Move the selection cursor (Up/Left/Down/Right).               |
| **Arrow Left**    | Previous Page.                                                |
| **Arrow Right**   | Next Page.                                                    |
| **Shift + WASD**  | Select a range of blocks (Multi-select).                      |
| **Shift + Click** | Select a range from the previous anchor to the clicked block. |

### Mouse Controls

- **Hover:** View live entropy and spectral stats for the block under the cursor.
- **Click:** Lock selection on a block to view Hex Dump and Architecture Analysis in the Inspector panel.

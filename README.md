<div align="center">

```
 ____  ____  ____  ___   __   _  _  _  _  __ _  ____  ____  ____ 
/ ___)(_  _)(  __)/ __) /  \ / )( \/ )( \(  ( \(_  _)(  __)(  _ \
\___ \  )(   ) _)( (_ \(  O )) __ () \/ (/    /  )(   ) _)  )   /
(____/ (__) (____)\___/ \__/ \_)(_/\____/\_)__) (__) (____)(__\_)
```

# StegoHunter

**Detect, locate, crack, and extract hidden data from images and audio.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-4B8BBE?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-53%20passed-2ea44f?style=flat-square)](tests/test_stegohunter.py)
[![Version](https://img.shields.io/badge/version-0.3.0-blue?style=flat-square)](pyproject.toml)

An elite CLI and Web steganalysis toolkit built for **OSINT**, **CTF**, and **digital forensics**.
It hunts hidden payloads using **mathematical embedding rate estimators (RS & SPA)**, **JPEG DCT frequency domain analysis**,
**audio spectrogram waterfalls**, **spatial heatmaps**, **EXIF/metadata discrepancies**, **steghide/ZIP cracking**,
and **automated batch triage with self-contained HTML forensic reports**.

</div>

---

## Features

- 📐 **RS Steganalysis & Sample Pair Analysis (SPA)** — mathematically estimates exact payload embedding rates (e.g. *14.8% in green channel*) and payload sizes in bytes without needing any header or length prefix
- 🌊 **Audio Spectrogram & Frequency Waterfall** — converts audio into 2D Short-Time Fourier Transform (STFT) frequency waterfalls, revealing ultrasonic drawings, text, and Morse code hidden in inaudible frequencies
- 🕵️ **EXIF, Metadata & Ghost Thumbnail Discrepancies** — inspects PNG ancillary chunks (`tEXt`, `zTXt`, `iTXt`), custom covert chunks, EXIF tag strings for base64/hex flags, and compares embedded EXIF preview thumbnails against displayed pictures to catch visual discrepancies
- 🔓 **Multi-Threaded Stego Passphrase Cracker** — attacks encrypted stego carriers (appended ZIPs, Steghide, OutGuess, keyed LSB) using wordlists with high-speed multi-threading
- 📂 **Recursive Batch Triage & Forensic HTML Reports** — sweeps entire folders across CPU cores and compiles self-contained, offline interactive HTML forensic exhibits
- 🌐 **Interactive Web Lab (`stegohunter serve`)** — zero-install browser GUI featuring drag-and-drop analysis, StegSolve-style bit-plane cycling (bits 0–7, R/G/B/Alpha, Invert), real-time heatmap opacity sliders, and one-click payload downloads
- 🗺️ **Visual Heatmaps & Bit-Plane Slicing** — generates localized spatial heatmaps highlighting where stego clusters are packed
- ⚡ **JPEG DCT Frequency Steganalysis** — detects **JSteg** (Westfeld Chi-Square PoV equalization), **F5** (shrinkage zero-inflation), and **OutGuess** (boundary discontinuity) directly from 8x8 block quantized DCT tables
- 🎨 **Palette Analysis** — audits duplicate colors, palette gaps, non-zero padding, and skewed color-frequency distributions in indexed images
- 📎 **Appended-Data Scanning** — carves trailing bytes past true EOI/IEND markers and recognizes magic bytes (ZIP, RAR, GZIP, PDF, ELF, etc.)
- 🔊 **WAV Audio LSB Analysis** — compares least-significant bit plane entropy against most-significant bit controls

---

## Installation

```bash
# Clone the repository
git clone https://github.com/AIwolfie/StegoHunter.git
cd StegoHunter

# Install with development dependencies
pip install -e ".[dev]"
```

Verify the install:

```bash
stegohunter --version
# stegohunter 0.3.0
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `Pillow` | Image loading, bit-plane manipulation, and visualization rendering |
| `numpy` | Fast array operations, 2D block DCT math, and STFT audio processing |
| `pytest` | Test suite (dev dependency) |

---

## Usage

### 1. Full Multi-Vector Analysis

```bash
# Scan an image
stegohunter analyze target.jpg

# Scan an audio file
stegohunter analyze target.wav
```

```text
[ARCHIVE: ONLINE — StegoHunter]
  target:   target.jpg
  type:     image
  verdict:  SUSPICIOUS

  -- LSB --
  size:           256x256
  pixels:         65536
  chi2 p-value:   0.000000
  LSB entropy:    0.9998
  MSB entropy:    0.9412  (control)
  status:         SUSPICIOUS

  -- RS / SPA --
  mean RS rate:   16.42%
  mean SPA rate:  14.18%
  channels:       R: 12.1%, G: 24.8%, B: 12.4%
  est. payload:   4034 bytes
  - RS Analysis: ~24.8% estimated LSB modification in G channel
  status:         SUSPICIOUS

  -- DCT --
  JSteg detected: YES
  chi2 p-value:   0.998241
  F5 zero ratio:  82.14% (normal)
  blockiness:     1.1240
  AC LSB entropy: 0.9992 (ratio 0.4998)
  status:         SUSPICIOUS

  -- METADATA --
  EXIF tags:      14
  ghost thumbnail:YES (diff=31.40%)
  - Ghost Thumbnail Discrepancy detected (diff=31.40%): embedded EXIF thumbnail diverges from displayed image
  status:         SUSPICIOUS

  -- APPENDED --
  appended:       no

  -> Run `stegohunter visualize <image> -o heatmap.png` to inspect spatial anomalies.
```

---

### 2. Audio Spectrogram Waterfall

Convert audio into a 2D frequency waterfall image to expose visual steganography hidden in high-frequency audio bands:

```bash
# Generate waterfall spectrogram (inferno colormap)
stegohunter spectrogram audio.wav -o waterfall.png

# Custom colormap & FFT resolution
stegohunter spectrogram audio.wav -o waterfall.png --colormap cyber --fft 2048
```

---

### 3. Stego Passphrase Cracker (`crack`)

Dictionary attack on encrypted stego carriers using multi-threading:

```bash
# Crack using built-in high-probability passphrase list
stegohunter crack suspicious.jpg

# Crack using a custom wordlist (e.g. rockyou.txt) across 16 worker threads
stegohunter crack suspicious.jpg -w /path/to/wordlist.txt --workers 16 -o decrypted_secret.bin
```

---

### 4. Batch Directory Triage & HTML Reports (`triage`)

Scan entire folders recursively and generate a standalone, offline interactive HTML forensic exhibit:

```bash
# Triage a directory and generate HTML forensic dashboard
stegohunter triage ./evidence_directory/ -r --workers 8 --html triage_report.html

# Also output machine-readable JSON
stegohunter triage ./evidence_directory/ -r --json findings.json
```

---

### 5. Interactive Browser Lab (`serve`)

Launch the local web dashboard for point-and-click StegSolve bit-plane exploration:

```bash
stegohunter serve --port 8080
```
Open `http://127.0.0.1:8080` in any web browser to drag-and-drop images, toggle bit planes, adjust heatmap sliders, and download extracted payloads.

---

### 6. Visual Heatmaps & Bit-Plane Slicing (`visualize`)

```bash
# Spatial anomaly heatmap (suspicious clusters glow red)
stegohunter visualize suspicious.png -o heatmap.png --mode heatmap --block-size 16 --alpha 0.5

# 8-bitplane composite grid (Bits 0-7)
stegohunter visualize suspicious.png -o bitgrid.png --mode grid

# High-contrast slice of a specific bit plane (e.g. Blue Channel Bit 0 LSB)
stegohunter visualize suspicious.png -o slice.png --mode bitplane --channel B --bit 0
```

---

### 7. Extraction

```bash
# Extract LSB message from image
stegohunter extract-lsb image.png -o message.bin

# Extract data appended past EOI marker
stegohunter extract-appended image.jpg -o appended.bin

# Extract LSB payload from WAV audio
stegohunter extract-audio audio.wav -o message.bin
```

---

## Command Reference

| Command | Description | Exit Code |
|---------|-------------|:---------:|
| `analyze <file>` | Run full detection suite across all modules | `0` clean · `2` suspicious |
| `visualize <file>` | Generate spatial anomaly heatmap or bit-plane slices | `0` / `1` |
| `spectrogram <file>` | Generate audio frequency waterfall spectrogram PNG | `0` / `1` |
| `crack <file>` | Multi-threaded dictionary attack on stego carriers | `0` / `1` |
| `triage <dir>` | Batch sweep directory with HTML forensic reporting | `0` clean · `2` suspicious |
| `serve` | Launch local interactive web lab / StegSolve GUI | `0` |
| `extract-lsb <file>` | Extract hidden LSB message from an image | `0` / `1` |
| `extract-appended <file>` | Extract data trailing the file marker | `0` / `1` |
| `extract-audio <file>` | Extract LSB payload from WAV audio | `0` / `1` |
| `rs <file>` | Mathematical RS & Sample Pair Analysis (JSON) | `0` |
| `metadata <file>` | EXIF, PNG chunks, and Ghost Thumbnail analysis (JSON) | `0` |
| `dct <file>` | JPEG DCT frequency domain analysis (JSON) | `0` |
| `lsb <file>` | LSB bit-plane analysis (JSON) | `0` |
| `palette <file>` | Palette covert channel analysis (JSON) | `0` |
| `appended <file>` | Appended data scan (JSON) | `0` |
| `audio <file>` | WAV audio bit-plane analysis (JSON) | `0` |

---

## Architecture & Detection Theory

### 1. RS Steganalysis & Sample Pair Analysis (Fridrich / Dumitrescu)
Detects randomly-scattered LSB stego with mathematical precision. By grouping pixels into non-overlapping groups and computing flipping operations $F_1$ and $F_{-1}$, the algorithm analyzes the divergence between regular ($R_M$) and singular ($S_M$) groups to solve for the exact percentage of modified pixels without requiring any length header.

### 2. Frequency Domain (JPEG DCT)
Inspects quantized frequency coefficients directly from 8x8 block tables.
- **JSteg:** Westfeld Chi-Square tests equality of frequency value pairs $(2k, 2k+1)$.
- **F5:** Identifies coefficient shrinkage toward zero (zero-bin inflation).
- **OutGuess:** Measures 8x8 block boundary discontinuity across grid edges.

### 3. Audio Waterfall Spectrograms
Calculates Short-Time Fourier Transform (STFT) magnitude in decibels and applies perceptual colormaps to expose hidden drawings or text modulated into audio frequencies.

### 4. Metadata & Ghost Thumbnail Discrepancies
Audits auxiliary PNG chunks (`tEXt`, `zTXt`, `iTXt`), decodes base64/hex in EXIF tags, and flags instances where an embedded preview thumbnail differs from the main image.

---

## Project Structure

```
stegohunter/
├── stegohunter/
│   ├── __init__.py
│   ├── cli.py                 # Unified CLI interface
│   ├── orchestrator.py        # Multi-vector pipeline orchestrator
│   ├── visualizer.py          # Spatial heatmaps, bit-plane slicing & grids
│   ├── cracker.py             # Multi-threaded passphrase cracker
│   ├── triage.py              # Batch directory scanner
│   ├── reporting.py           # Self-contained HTML report compiler
│   ├── server.py              # Interactive web lab & StegSolve GUI
│   ├── analyzers/
│   │   ├── lsb.py             # LSB bit-plane analysis
│   │   ├── rs.py              # RS & Sample Pair Analysis (SPA)
│   │   ├── jpeg_dct.py        # JPEG DCT frequency & marker analysis
│   │   ├── metadata.py        # EXIF, PNG chunks & Ghost Thumbnails
│   │   ├── palette.py         # Palette covert channel detection
│   │   ├── appended.py        # Appended data scanning
│   │   └── common.py          # Entropy & histogram utilities
│   ├── audio/
│   │   ├── wav.py             # WAV LSB analysis & extraction
│   │   └── spectrogram.py     # STFT audio waterfall spectrogram generator
│   └── extractors/
│       ├── lsb.py             # Image LSB message extraction
│       └── appended.py        # Appended data extraction
├── tests/
│   └── test_stegohunter.py    # 53 self-contained automated tests
├── pyproject.toml             # Packaging, dependencies & entry point
└── README.md
```

---

## Testing

```bash
pytest tests/ -v
```

All 53 tests run self-contained sample generators verifying detection, extraction, math models, cracking, triage, and web server endpoints without external fixtures.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

<div align="center">

*StegoHunter — hunting the payloads hidden in plain sight.*

</div>

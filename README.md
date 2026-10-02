<div align="center">

```
 ____  ____  ____  ___   __   _  _  _  _  __ _  ____  ____  ____ 
/ ___)(_  _)(  __)/ __) /  \ / )( \/ )( \(  ( \(_  _)(  __)(  _ \
\___ \  )(   ) _)( (_ \(  O )) __ () \/ (/    /  )(   ) _)  )   /
(____/ (__) (____)\___/ \__/ \_)(_/\____/\_)__) (__) (____)(__\_)
```

# StegoHunter

**Detect, locate, and extract hidden data from images and audio.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-4B8BBE?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-44%20passed-2ea44f?style=flat-square)](tests/test_stegohunter.py)
[![Version](https://img.shields.io/badge/version-0.2.0-blue?style=flat-square)](pyproject.toml)

A CLI steganalysis toolkit built for **OSINT**, **CTF**, and **digital forensics**.
It hunts hidden payloads using **spatial localization heatmaps**, **JPEG DCT frequency domain analysis**,
**LSB bit-plane slicing**, **palette analysis**, and **appended-data scanning** — across images and audio.

</div>

---

## Features

- 🗺️ **Visual Heatmaps & Bit-Plane Slicing** — generate spatial anomaly heatmaps (red/hot overlays) localizing exactly where payload bits are clustered; export individual bit-plane slices or 8-plane composite grids
- 🌊 **JPEG DCT Frequency Domain Analysis** — parse discrete cosine transform coefficients from 8x8 blocks before decompression; detect **JSteg** (Westfeld Chi-Square PoV equalization), **F5** (shrinkage zero-inflation), and **OutGuess** (blockiness boundary discontinuity)
- 🔍 **LSB Bit-Plane Analysis** — entropy, 0/1 ratio, and chi-square uniformity testing on every bit plane of RGB channels
- 🎨 **Palette Analysis** — detects duplicate colors, palette gaps, non-zero padding, and skewed color-frequency distributions in indexed images
- 📎 **Appended-Data Scanning** — finds bytes trailing the end-of-image marker and identifies embedded file signatures (ZIP, RAR, GZIP, PDF, PNG, JPEG, ELF…)
- 🔊 **WAV Audio Analysis** — LSB entropy vs. MSB control comparison plus chi-square testing for 8/16/24/32-bit samples
- 📦 **Message Extraction** — recovers length-prefixed and NULL-terminated payloads from images and audio
- 📊 **Full-Pipeline Verdicts** — `CLEAN`, `SUSPICIOUS`, or `HIDDEN DATA LIKELY` with per-module evidence
- 🎯 **JSON Output** for low-level modules — drop straight into your automated forensics pipelines

---

## Installation

```bash
# Clone the repository
git clone https://github.com/AIwolfie/StegoHunter.git
cd StegoHunter

# Install with development dependencies (includes pytest)
pip install -e ".[dev]"
```

Verify the install:

```bash
stegohunter --version
# stegohunter 0.2.0
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `Pillow` | Image loading, bit-plane manipulation, and visualization rendering |
| `numpy` | High-performance array operations and 2D block DCT math |
| `pytest` | Test suite (dev dependency) |

---

## Usage

### 1. Full analysis pipeline

```bash
# Scan an image (PNG, JPEG, BMP, GIF, WebP...)
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

  -- DCT --
  JSteg detected: YES
  chi2 p-value:   0.998241
  F5 zero ratio:  82.14% (normal)
  blockiness:     1.1240
  AC LSB entropy: 0.9992 (ratio 0.4998)
  - JSteg detected: DCT pairs equalized (chi2=2.15, p=0.9982, pairs=18)
  status:         SUSPICIOUS

  -- APPENDED --
  appended:       no

  -> Run `stegohunter visualize <image> -o heatmap.png` to inspect spatial anomalies.
```

### 2. Visual Heatmaps & Bit-Plane Visualization

```bash
# Generate a spatial anomaly heatmap overlay (suspicious blocks glow yellow/red)
stegohunter visualize suspicious.png -o heatmap.png --mode heatmap --block-size 16 --alpha 0.5

# Generate an 8-panel composite comparison grid (Bit 0 LSB through Bit 7 MSB)
stegohunter visualize suspicious.png -o bitplanes.png --mode grid --channel R

# Extract a single high-contrast bit-plane slice (e.g. true LSB bit 0 of Blue channel)
stegohunter visualize suspicious.png -o lsb_b0.png --mode bitplane --channel B --bit 0
```

### 3. Extraction

```bash
# Extract an LSB message from an image
stegohunter extract-lsb image.png -o message.bin

# Extract data appended after the end-of-image marker
stegohunter extract-appended image.jpg -o appended.bin

# Extract an LSB message from WAV audio
stegohunter extract-audio audio.wav -o message.bin
```

### 4. Low-level modules (JSON output)

```bash
stegohunter dct image.jpg       # JPEG DCT frequency domain analysis
stegohunter lsb image.png       # LSB analysis only
stegohunter palette image.png   # Palette analysis only
stegohunter appended file.bin   # Appended-data scan only
stegohunter audio audio.wav     # WAV audio LSB analysis only
```

---

## Command Reference

| Command | Description | Exit |
|---------|-------------|------|
| `analyze <file>` | Run the full detection suite and print a verdict | `0` clean · `2` suspicious |
| `visualize <file>` | Generate spatial anomaly heatmap or bit-plane slices | `0` / `1` |
| `extract-lsb <file>` | Extract a hidden LSB message from an image | `0` / `1` |
| `extract-appended <file>` | Extract data appended after the EOI marker | `0` / `1` |
| `extract-audio <file>` | Extract an LSB message from a WAV file | `0` / `1` |
| `dct <file>` | JPEG DCT frequency domain analysis (JSON) | `0` |
| `lsb <file>` | LSB bit-plane analysis (JSON) | `0` |
| `palette <file>` | Palette analysis (JSON) | `0` |
| `appended <file>` | Appended-data scan (JSON) | `0` |
| `audio <file>` | WAV audio LSB analysis (JSON) | `0` |

### `visualize` options

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output image path | `<file>_heatmap.png` |
| `-m, --mode` | Visualization mode: `heatmap`, `bitplane`, `grid` | `heatmap` |
| `-b, --bit` | Bit plane index (`0`=LSB to `7`=MSB) | `0` |
| `-c, --channel` | Channel: `R`, `G`, `B`, `all`, `gray` | `all` |
| `--block-size` | Block window size in pixels for heatmap | `16` |
| `--alpha` | Overlay blend alpha (`0.0`=heatmap only, `1.0`=original, `0.5`=50% blend) | `0.5` |

---

## Detection & Forensics Architecture

### 1. Spatial Localization Heatmaps (`visualize`)
Standard analysis outputs a number (e.g. "suspicious entropy 0.99"). StegoHunter breaks the image into sliding blocks, measures local LSB entropy and 0/1 bit deviation, and renders a color-coded heatmap (Deep Blue $\to$ Cyan $\to$ Green $\to$ Yellow $\to$ Crimson Red). Blocks packed with stego payloads glow red, highlighting watermarks, hidden QR codes, or rectangular stego fields visually.

### 2. JPEG DCT Frequency Domain Analysis (`dct`)
Tools like JSteg, F5, and OutGuess embed secrets in the mathematical frequency domain (quantized AC DCT coefficients) rather than raw pixels.
- **JSteg Detection:** Westfeld Chi-Square on Pairs of Values (PoVs). JSteg balances pairs $(2k, 2k+1)$, causing the chi-square $p$-value to spike toward $1.0$.
- **F5 Detection:** F5 uses matrix embedding with shrinkage, driving non-zero coefficients toward zero. StegoHunter catches the resulting zero-bin inflation and histogram asymmetry.
- **OutGuess Detection:** Computes inter-block vs. intra-block boundary discontinuity (blockiness calibration) across 8x8 DCT grid edges.
- **Marker Inspection:** Scans raw binary segments for hidden `COM` comment strings and non-standard `APP` payloads.

### 3. LSB Bit-Plane Analysis (`lsb`)
Tests RGB bit planes for 4-byte length-prefix headers followed by ASCII payloads, low entropy in natural images, and chi-square distribution anomalies.

### 4. Palette Covert-Channel Analysis (`palette`)
Finds hidden data in indexed images (GIF, palette-PNG) by auditing color duplication, unreferenced palette gaps, non-zero trailing padding, and skewed color-frequency distributions.

### 5. Appended-Data Scanning (`appended`)
Locates the true End-Of-Image (EOI) marker and scans all bytes beyond it, recognizing magic bytes for ZIP, RAR, GZIP, BZ2, XZ, PDF, PNG, JPEG, ELF, and ZSTD.

### 6. Audio LSB Forensics (`audio`)
Evaluates WAV audio bit streams by contrasting the noise characteristics of least-significant bit planes against most-significant bit controls.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Analysis complete — file is clean |
| `2` | Analysis complete — suspicious / hidden data likely |
| `1` | Error (file not found, unsupported type, extraction failed) |

---

## Project Structure

```
stegohunter/
├── stegohunter/
│   ├── __init__.py
│   ├── cli.py                 # CLI interface & subcommands
│   ├── orchestrator.py        # Multi-module pipeline orchestrator
│   ├── visualizer.py          # Spatial heatmaps, bit-plane slicing, grid
│   ├── analyzers/
│   │   ├── lsb.py             # LSB bit-plane analysis
│   │   ├── jpeg_dct.py        # JPEG DCT frequency & marker analysis
│   │   ├── palette.py         # Palette covert-channel detection
│   │   ├── appended.py        # Appended-data scanning
│   │   └── common.py          # Shared utilities (entropy, histograms)
│   ├── audio/
│   │   └── wav.py             # WAV audio LSB analysis & extraction
│   └── extractors/
│       ├── lsb.py             # Image LSB message extraction
│       └── appended.py        # Appended-data extraction
├── tests/
│   └── test_stegohunter.py    # 44 self-contained tests
├── pyproject.toml             # Packaging and dependencies
└── README.md
```

---

## Testing

The test suite **generates its own clean and stego samples** and verifies detection and extraction round-trip correctness:

```bash
pytest tests/ -v
```

Coverage:
- 44 tests covering spatial LSB, JPEG DCT (JSteg, F5, OutGuess, markers), visual heatmaps, bit-plane grids, palette covert channels, appended files, WAV audio, orchestrator pipeline, and CLI subcommands.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

<div align="center">

*StegoHunter — hunting the payloads hidden in plain sight.*

</div>

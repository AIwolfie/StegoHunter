<div align="center">

```
 ____  ____  ____  ___   __   _  _  _  _  __ _  ____  ____  ____ 
/ ___)(_  _)(  __)/ __) /  \ / )( \/ )( \(  ( \(_  _)(  __)(  _ \
\___ \  )(   ) _)( (_ \(  O )) __ () \/ (/    /  )(   ) _)  )   /
(____/ (__) (____)\___/ \__/ \_)(_/\____/\_)__) (__) (____)(__\_)
```

# StegoHunter

**Detect and extract hidden data from images and audio.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-4B8BBE?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-34%20passed-2ea44f?style=flat-square)](tests/test_stegohunter.py)

A CLI steganalysis toolkit built for **OSINT**, **CTF**, and **digital forensics**.
It hunts hidden payloads using **LSB bit-plane analysis**, **palette analysis**,
and **appended-data scanning** — across images and audio.

</div>

---

## Features

- 🔍 **LSB bit-plane analysis** — entropy, 0/1 ratio, and chi-square uniformity
  testing on every bit plane of the RGB channels
- 🎨 **Palette analysis** — detects duplicate colors, palette gaps, non-zero
  padding, and skewed color-frequency distributions in indexed images
- 📎 **Appended-data scanning** — finds bytes trailing the end-of-image marker
  and identifies embedded file signatures (ZIP, RAR, GZIP, PDF, PNG, JPEG, ELF…)
- 🔊 **WAV audio analysis** — LSB entropy vs. MSB control comparison plus
  chi-square testing for 8/16/24/32-bit samples
- 📦 **Message extraction** — recovers length-prefixed and NULL-terminated
  payloads from images and audio
- 📊 **Full-pipeline verdicts** — `CLEAN`, `SUSPICIOUS`, or `HIDDEN DATA LIKELY`
  with per-module evidence
- 🎯 **JSON output** for low-level modules — drop straight into your scripts

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/stegohunter.git
cd stegohunter

# Install with development dependencies (includes pytest)
pip install -e ".[dev]"
```

Verify the install:

```bash
stegohunter --version
# stegohunter 0.1.0
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `Pillow` | Image loading and pixel access |
| `numpy` | Numerical / array operations |
| `pytest` | Test suite (dev dependency) |

---

## Usage

### Full analysis pipeline

```bash
# Scan an image
stegohunter analyze image.png

# Scan an audio file
stegohunter analyze audio.wav
```

```
[ARCHIVE: ONLINE — StegoHunter]
  target:   image.png
  type:     image
  verdict:  SUSPICIOUS

  -- LSB --
  size:           100x100
  pixels:         10000
  chi2 p-value:   0.154477
  LSB entropy:    0.9999
  MSB entropy:    0.9996  (control)
  est. msg len:   27 bytes
  - LSB stream begins with 27-byte length prefix followed by ASCII content
  status:         SUSPICIOUS

  -- APPENDED --
  appended:       no
```

### Extraction

```bash
# Extract an LSB message from an image
stegohunter extract-lsb image.png -o message.bin

# Extract data appended after the end-of-image marker
stegohunter extract-appended image.jpg -o appended.bin

# Extract an LSB message from WAV audio
stegohunter extract-audio audio.wav -o message.bin
```

### Low-level modules (JSON output)

```bash
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
| `extract-lsb <file>` | Extract a hidden LSB message from an image | `0` / `1` |
| `extract-appended <file>` | Extract data appended after the EOI marker | `0` / `1` |
| `extract-audio <file>` | Extract an LSB message from a WAV file | `0` / `1` |
| `lsb <file>` | LSB bit-plane analysis (JSON) | `0` |
| `palette <file>` | Palette analysis (JSON) | `0` |
| `appended <file>` | Appended-data scan (JSON) | `0` |
| `audio <file>` | WAV audio LSB analysis (JSON) | `0` |

### `extract-lsb` options

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output file path | `<file>.lsb.bin` |
| `-m, --mode` | Extraction mode: `auto`, `row`, `single` | `auto` |
| `-b, --bit` | Bit plane for `single` mode | `0` |
| `-c, --channel` | Channel for `single` mode: `R`, `G`, `B` | — |
| `--max-bytes` | Maximum bytes to extract | `8192` |

---

## Detection Methods

### 1. LSB Analysis (`lsb`)

Hidden data is often written into the least-significant bits of pixel values,
where it is visually imperceptible. StegoHunter tests every bit plane for:

- **Length-prefix fingerprints** — a 4-byte message-length header followed by
  printable ASCII is a strong embedded-payload indicator
- **Entropy anomalies** — the true LSB plane of a natural image is near-random
  (entropy ≈ 1.0); a structured LSB plane signals tampering
- **Chi-square uniformity** — a low *p*-value rejects the hypothesis that
  LSB bit-pairs are uniformly distributed

### 2. Palette Analysis (`palette`)

Indexed images (GIF, palette-PNG) hide data by reordering or editing palette
entries. StegoHunter looks for:

- **Duplicate color entries** in the palette
- **Gaps** in the defined palette region
- **Non-zero padding** in unused trailing entries
- **Skewed color-frequency entropy**

### 3. Appended-Data Scanning (`appended`)

A common trick is appending a whole archive or file after the legitimate
end-of-image marker. StegoHunter locates the EOI marker for the format, then
analyzes everything after it:

- Detects **trailing bytes** and reports their offset, size, and entropy
- Identifies **known file signatures**: ZIP, RAR, GZIP, BZ2, XZ, PDF, PNG,
  JPEG, ELF, ZSTD

### 4. Audio LSB Analysis (`audio`)

For WAV files, StegoHunter compares the **LSB plane** against the **MSB plane**
as a control: natural audio has structured MSBs and noisy LSBs. A structured
LSB stream, or one that rejects chi-square uniformity, indicates an embedded
message.

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
│   ├── cli.py                 # Command-line interface
│   ├── orchestrator.py        # Full-pipeline analysis and verdicts
│   ├── analyzers/
│   │   ├── lsb.py             # LSB bit-plane detection
│   │   ├── palette.py         # Palette-based detection
│   │   ├── appended.py        # Appended-data scanning
│   │   └── common.py          # Shared utilities (entropy, histograms)
│   ├── audio/
│   │   └── wav.py             # WAV LSB analysis and extraction
│   └── extractors/
│       ├── lsb.py             # LSB message extraction
│       └── appended.py        # Appended-data extraction
├── tests/
│   └── test_stegohunter.py    # 34 tests with self-generated samples
├── pyproject.toml             # Packaging and entry point
└── README.md
```

---

## Testing

The test suite **generates its own stego samples** and verifies that detection
and extraction round-trip correctly — no external fixtures required.

```bash
pytest tests/ -v
```

Coverage includes:

- Entropy and histogram utilities
- LSB detection on clean vs. embedded images
- Length-prefixed and NULL-terminated message extraction
- Clean vs. covert-channel palette images
- Appended-data detection and extraction (including embedded ZIPs)
- WAV LSB analysis and extraction
- Full orchestrator verdicts and CLI command behavior
- End-to-end image, audio, and appended-data round-trips

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

*StegoHunter — hunting the payloads hidden in plain sight.*

</div>

"""StegoHunter CLI — detect and extract hidden data from images and audio."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from . import __version__
from .orchestrator import full_analyze, is_image, is_audio
from .analyzers import analyze_lsb, analyze_palette, find_appended_data
from .extractors import extract_lsb_message, extract_appended_data
from .audio import analyze_lsb_wav, extract_lsb_wav

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _c(text: str, color: str) -> str:
    """Colorize if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text


def _verdict_color(verdict: str) -> str:
    if verdict == "CLEAN":
        return GREEN
    if verdict == "SUSPICIOUS":
        return YELLOW
    if verdict == "HIDDEN DATA LIKELY":
        return RED
    return DIM


def cmd_analyze(args: argparse.Namespace) -> int:
    report = full_analyze(args.file)

    if report["verdict"] == "NOT FOUND":
        print(_c(f"[!] File not found: {args.file}", RED))
        return 1
    if report["verdict"] == "UNSUPPORTED":
        print(_c(f"[!] Unsupported file type: {args.file}", YELLOW))
        return 1

    print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
    print(_c(f"  target:   {args.file}", BOLD))
    print(f"  type:     {report['type']}")
    print(f"  verdict:  {_c(report['verdict'], _verdict_color(report['verdict']))}")
    print()

    for finding in report["findings"]:
        mod = finding["module"]
        print(_c(f"  -- {mod.upper()} --", CYAN))

        if mod == "lsb":
            print(f"  size:           {finding['image_size'][0]}x{finding['image_size'][1]}")
            print(f"  pixels:         {finding['total_pixels']}")
            print(f"  chi2 p-value:   {finding['chi_square_p_value']:.6f}")
            print(f"  LSB entropy:    {finding['lsb_entropy']}")
            print(f"  MSB entropy:    {finding['msb_entropy']}  (control)")
            if finding["recomputed_message_length"]:
                print(f"  est. msg len:   {finding['recomputed_message_length']} bytes")
            for r in finding.get("reasons", []):
                print(f"  - {r}")
            status = "SUSPICIOUS" if finding["suspicious"] else "clean"
            print(f"  status:         {_c(status, _verdict_color(status))}")

        elif mod == "palette":
            if not finding["has_palette"]:
                print(f"  note:   {finding['details'][0]}")
            else:
                print(f"  palette size:   {finding['palette_size']} / {finding['max_palette_size']}")
                print(f"  used colors:    {finding['used_colors']}")
                print(f"  duplicates:     {finding['duplicate_colors']}")
                print(f"  freq entropy:   {finding['color_frequency_entropy']}")
                for d in finding["details"]:
                    print(f"  - {d}")
                status = "SUSPICIOUS" if finding["suspicious"] else "clean"
                print(f"  status:         {_c(status, _verdict_color(status))}")

        elif mod == "audio_lsb":
            print(f"  format:         {finding['bits_per_sample']}-bit, {finding['num_channels']}ch")
            print(f"  sample rate:    {finding['sample_rate']} Hz")
            print(f"  samples:        {finding['sample_count']}")
            print(f"  LSB entropy:    {finding['lsb_entropy']}")
            print(f"  LSB 1-ratio:    {finding['lsb_ratio']}")
            print(f"  MSB entropy:    {finding['msb_entropy']}  (control)")
            print(f"  chi2 p-value:   {finding['chi_square_p']}")
            if finding["recomputed_message_length"]:
                print(f"  est. msg len:   {finding['recomputed_message_length']} bytes")
            if finding["note"]:
                print(f"  note:           {finding['note']}")
            status = "SUSPICIOUS" if finding["suspicious"] else "clean"
            print(f"  status:         {_c(status, _verdict_color(status))}")

        elif mod == "appended":
            if finding.get("appended"):
                print(f"  appended:       YES at offset {finding['offset']} ({finding['size']} bytes)")
                print(f"  entropy:        {finding['entropy']}")
                if finding.get("contains_text"):
                    print(f"  content:        looks like TEXT")
                if finding.get("found_signatures"):
                    print(f"  signatures:     {', '.join(finding['found_signatures'])}")
                elif finding.get("contains_zip"):
                    print(f"  signatures:     ZIP")
            else:
                print(f"  appended:       no")
        print()

    if report["verdict"] == "HIDDEN DATA LIKELY":
        print(_c("  -> Run `stegohunter extract` to pull out the hidden data.", YELLOW))
    return 0 if report["verdict"] == "CLEAN" else 2


def cmd_extract_lsb(args: argparse.Namespace) -> int:
    if not is_image(args.file):
        print(_c(f"[!] LSB extraction supports images only: {args.file}", RED))
        return 1

    channel = args.channel
    mode = args.mode
    if channel and mode != "single":
        mode = "single"

    result = extract_lsb_message(
        args.file,
        mode=mode,
        bit=args.bit,
        channel=channel,
        max_bytes=args.max_bytes,
    )
    data = result["extracted"]
    print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
    print(f"  mode:     {result['mode_used']}")
    print(f"  length:   {result['length']} bytes")
    if result["null_terminated"]:
        print(f"  ended at: NULL terminator")

    out_path = args.output
    if out_path is None:
        base = os.path.splitext(args.file)[0]
        out_path = f"{base}.lsb.bin"

    with open(out_path, "wb") as f:
        f.write(data)
    print(f"  wrote:    {out_path}")

    # Try to show printable content
    printable = bytes(b if 32 <= b < 127 else 46 for b in data[:200])
    if printable.strip(b"."):
        print(f"  preview:  {printable.decode('ascii', errors='replace')!r}")
    return 0


def cmd_extract_appended(args: argparse.Namespace) -> int:
    result = extract_appended_data(args.file, output_path=args.output)
    if not result.get("appended"):
        print(_c(f"[!] No appended data found in {args.file}", YELLOW))
        return 1
    print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
    print(f"  offset:   {result['offset']}")
    print(f"  size:     {result['size']} bytes")
    print(f"  wrote:    {result['output_path']}")
    return 0


def cmd_extract_audio(args: argparse.Namespace) -> int:
    if not is_audio(args.file):
        print(_c(f"[!] Audio extraction supports WAV only: {args.file}", RED))
        return 1
    result = extract_lsb_wav(args.file, max_bytes=args.max_bytes)
    data = result["extracted"]
    print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
    print(f"  format:   {result['bits_per_sample']}-bit, {result['channels']}ch")
    print(f"  length:   {result['length']} bytes")

    out_path = args.output
    if out_path is None:
        base = os.path.splitext(args.file)[0]
        out_path = f"{base}.lsb.bin"
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"  wrote:    {out_path}")
    printable = bytes(b if 32 <= b < 127 else 46 for b in data[:200])
    if printable.strip(b"."):
        print(f"  preview:  {printable.decode('ascii', errors='replace')!r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegohunter",
        description="Detect and extract hidden data from images and audio.",
        epilog="Modules: LSB bit-plane analysis, palette analysis, appended-data scan, WAV audio LSB.",
    )
    parser.add_argument("--version", action="version", version=f"stegohunter {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Run full detection suite on a file")
    p_analyze.add_argument("file")
    p_analyze.set_defaults(func=cmd_analyze)

    # extract-lsb
    p_lsb = sub.add_parser("extract-lsb", help="Extract LSB hidden message from an image")
    p_lsb.add_argument("file")
    p_lsb.add_argument("-o", "--output", help="Output file (default: <file>.lsb.bin)")
    p_lsb.add_argument("-m", "--mode", choices=["auto", "row", "single"], default="auto",
                       help="Extraction mode")
    p_lsb.add_argument("-b", "--bit", type=int, default=0, help="Bit plane for single mode")
    p_lsb.add_argument("-c", "--channel", choices=["R", "G", "B"],
                       help="Channel for single mode")
    p_lsb.add_argument("--max-bytes", type=int, default=8192)
    p_lsb.set_defaults(func=cmd_extract_lsb)

    # extract-appended
    p_app = sub.add_parser("extract-appended", help="Extract data appended after EOI marker")
    p_app.add_argument("file")
    p_app.add_argument("-o", "--output", help="Output file (default: <file>_appended<ext>)")
    p_app.set_defaults(func=cmd_extract_appended)

    # extract-audio
    p_audio = sub.add_parser("extract-audio", help="Extract LSB message from WAV audio")
    p_audio.add_argument("file")
    p_audio.add_argument("-o", "--output", help="Output file (default: <file>.lsb.bin)")
    p_audio.add_argument("--max-bytes", type=int, default=65536)
    p_audio.set_defaults(func=cmd_extract_audio)

    # ---- low-level subcommands for power users ----
    p_lsb_d = sub.add_parser("lsb", help="Run only LSB analysis")
    p_lsb_d.add_argument("file")
    p_lsb_d.set_defaults(func=lambda a: _dump_json(analyze_lsb(a.file)))

    p_pal = sub.add_parser("palette", help="Run only palette analysis")
    p_pal.add_argument("file")
    p_pal.set_defaults(func=lambda a: _dump_json(analyze_palette(a.file)))

    p_app_d = sub.add_parser("appended", help="Run only appended-data scan")
    p_app_d.add_argument("file")
    p_app_d.set_defaults(func=lambda a: _dump_json(find_appended_data(a.file)))

    p_aud_d = sub.add_parser("audio", help="Run only WAV audio LSB analysis")
    p_aud_d.add_argument("file")
    p_aud_d.set_defaults(func=lambda a: _dump_json(analyze_lsb_wav(a.file)))

    return parser


def _dump_json(result: dict) -> int:
    import json
    print(json.dumps(result, indent=2, default=str))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    # Windows consoles default to cp1252; force UTF-8 so box-drawing and
    # em-dash glyphs in output render correctly.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
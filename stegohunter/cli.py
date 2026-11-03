"""StegoHunter CLI — detect and extract hidden data from images and audio."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from . import __version__
from .orchestrator import full_analyze, is_image, is_audio
from .analyzers import (
    analyze_lsb,
    analyze_palette,
    find_appended_data,
    analyze_jpeg_dct,
    analyze_rs,
    analyze_metadata,
)
from .extractors import extract_lsb_message, extract_appended_data
from .audio import analyze_lsb_wav, extract_lsb_wav, generate_spectrogram
from .visualizer import extract_bit_plane, generate_bitplane_grid, generate_spatial_heatmap
from .cracker import crack_passphrase
from .triage import triage_directory
from .reporting import generate_html_report
from .server import run_server

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

        elif mod == "dct":
            print(f"  JSteg detected: {'YES' if finding['jsteg_detected'] else 'no'}")
            print(f"  chi2 p-value:   {finding['jsteg_p_value']}")
            print(f"  F5 zero ratio:  {finding['f5_zero_ratio']:.2%} ({'YES' if finding['f5_detected'] else 'normal'})")
            print(f"  blockiness:     {finding['blockiness']:.4f}")
            print(f"  AC LSB entropy: {finding['ac_lsb_entropy']} (ratio {finding['ac_lsb_ratio']})")
            if finding.get("comments"):
                print(f"  comments:       {finding['comments']}")
            if finding.get("trailing_bytes"):
                print(f"  trailing bytes: {finding['trailing_bytes']}")
            for r in finding.get("reasons", []):
                print(f"  - {r}")
            status = "SUSPICIOUS" if finding["suspicious"] else "clean"
            print(f"  status:         {_c(status, _verdict_color(status))}")

        elif mod == "rs":
            print(f"  mean RS rate:   {finding['mean_rs_rate'] * 100:.2f}%")
            print(f"  mean SPA rate:  {finding['mean_spa_rate'] * 100:.2f}%")
            rates_str = ", ".join(f"{ch}: {r * 100:.1f}%" for ch, r in finding['rs_rates'].items())
            print(f"  channels:       {rates_str}")
            if finding.get("estimated_message_bytes"):
                print(f"  est. payload:   {finding['estimated_message_bytes']} bytes")
            for r in finding.get("reasons", []):
                print(f"  - {r}")
            status = "SUSPICIOUS" if finding["suspicious"] else "clean"
            print(f"  status:         {_c(status, _verdict_color(status))}")

        elif mod == "metadata":
            print(f"  EXIF tags:      {len(finding.get('exif_tags', {}))}")
            if finding.get("is_png"):
                print(f"  PNG chunks:     {finding['png_chunks_count']}")
            if finding.get("has_ghost_thumbnail"):
                print(f"  ghost thumbnail:YES (diff={finding['thumbnail_discrepancy_score']:.2%})")
            for r in finding.get("reasons", []):
                print(f"  - {r}")
            status = "SUSPICIOUS" if finding["suspicious"] else "clean"
            print(f"  status:         {_c(status, _verdict_color(status))}")
        print()

    if report["verdict"] == "HIDDEN DATA LIKELY":
        print(_c("  -> Run `stegohunter extract` to pull out the hidden data.", YELLOW))
    if report["verdict"] in ("SUSPICIOUS", "HIDDEN DATA LIKELY") and report["type"] == "image":
        print(_c("  -> Run `stegohunter visualize <image> -o heatmap.png` to inspect spatial anomalies.", CYAN))
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


def cmd_visualize(args: argparse.Namespace) -> int:
    if not is_image(args.file):
        print(_c(f"[!] Visualization supports images only: {args.file}", RED))
        return 1

    mode = args.mode
    out_path = args.output

    if mode == "bitplane":
        if out_path is None:
            base = os.path.splitext(args.file)[0]
            ch = args.channel.lower()
            out_path = f"{base}_plane_{ch}_b{args.bit}.png"
        img = extract_bit_plane(args.file, channel=args.channel, bit=args.bit)
        img.save(out_path)
        print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
        print(f"  mode:     bitplane")
        print(f"  channel:  {args.channel.upper()}")
        print(f"  bit:      {args.bit}")
        print(f"  wrote:    {out_path}")

    elif mode == "grid":
        if out_path is None:
            base = os.path.splitext(args.file)[0]
            out_path = f"{base}_bitplanes_grid.png"
        img = generate_bitplane_grid(args.file, channel=args.channel)
        img.save(out_path)
        print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
        print(f"  mode:     grid (bits 0-7)")
        print(f"  channel:  {args.channel.upper()}")
        print(f"  wrote:    {out_path}")

    else:  # heatmap (default)
        if out_path is None:
            base = os.path.splitext(args.file)[0]
            out_path = f"{base}_heatmap.png"
        img, metrics = generate_spatial_heatmap(
            args.file,
            block_size=args.block_size,
            channel=args.channel,
            alpha=args.alpha,
        )
        img.save(out_path)
        print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
        print(f"  mode:        heatmap")
        print(f"  block size:  {metrics['block_size']}px")
        print(f"  blocks:      {metrics['total_blocks']}")
        print(f"  mean anomaly:{metrics['mean_anomaly_score']}")
        print(f"  max anomaly: {metrics['max_anomaly_score']}")
        print(f"  suspicious:  {metrics['suspicious_blocks_pct']}% blocks")
        print(f"  wrote:       {out_path}")

    return 0


def cmd_spectrogram(args: argparse.Namespace) -> int:
    if not is_audio(args.file):
        print(_c(f"[!] Spectrogram generation supports WAV audio only: {args.file}", RED))
        return 1

    img, stats = generate_spectrogram(
        args.file,
        output_path=args.output,
        colormap=args.colormap,
        n_fft=args.fft,
        target_width=args.width,
        target_height=args.height,
    )
    print(_c(f"[ARCHIVE: ONLINE — StegoHunter]", CYAN))
    print(f"  mode:        spectrogram waterfall")
    print(f"  duration:    {stats['duration_seconds']}s ({stats['total_samples']} samples)")
    print(f"  sample rate: {stats['sample_rate']} Hz (Nyquist: {stats['nyquist_khz']} kHz)")
    print(f"  colormap:    {stats['colormap']}")
    print(f"  wrote:       {stats['output_path']}")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    print(_c(f"[ARCHIVE: ONLINE — StegoHunter Cracker]", CYAN))
    print(f"  target:      {args.file}")
    print(f"  wordlist:    {args.wordlist or 'Built-in Common Passphrases'}")
    print(f"  workers:     {args.workers}")

    def progress(done: int, total: int, current: str) -> None:
        if sys.stdout.isatty():
            sys.stdout.write(f"\r  testing: [{done}/{total}] {current[:20]:<20}")
            sys.stdout.flush()

    res = crack_passphrase(
        args.file,
        wordlist_path=args.wordlist,
        max_workers=args.workers,
        output_path=args.output,
        progress_callback=progress,
    )
    if sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 45 + "\r")

    if res["success"]:
        print(_c(f"  [+] PASSWORD CRACKED: {res['password']!r}", GREEN))
        print(f"  tool vector: {res['tool']}")
        print(f"  attempts:    {res['attempts']}")
        if res.get("output_path"):
            print(f"  extracted:   {res['output_path']} ({res['extracted_bytes_len']} bytes)")
        return 0
    else:
        print(_c(f"  [-] Exhausted {res['attempts']} passwords. No key match found.", YELLOW))
        return 1


def cmd_triage(args: argparse.Namespace) -> int:
    print(_c(f"[ARCHIVE: ONLINE — StegoHunter Batch Triage]", CYAN))
    print(f"  target dir:  {args.directory}")
    print(f"  recursive:   {args.recursive}")
    print(f"  workers:     {args.workers}")

    def progress(done: int, total: int, current: str) -> None:
        if sys.stdout.isatty():
            base = os.path.basename(current)
            sys.stdout.write(f"\r  scanning: [{done}/{total}] {base[:25]:<25}")
            sys.stdout.flush()

    results = triage_directory(
        args.directory,
        recursive=args.recursive,
        max_workers=args.workers,
        progress_callback=progress,
    )
    if sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 45 + "\r")

    total = len(results)
    clean_c = sum(1 for r in results if r.get("verdict") == "CLEAN")
    susp_c = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")
    hidden_c = sum(1 for r in results if r.get("verdict") == "HIDDEN DATA LIKELY")

    print(f"\n  triaged:     {total} files")
    print(_c(f"  hidden data: {hidden_c}", RED if hidden_c else DIM))
    print(_c(f"  suspicious:  {susp_c}", YELLOW if susp_c else DIM))
    print(_c(f"  clean:       {clean_c}", GREEN))

    if args.html:
        report_path = generate_html_report(results, args.html)
        print(_c(f"\n  [+] Forensic HTML Report saved: {report_path}", GREEN))

    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(_c(f"  [+] JSON report saved: {args.json}", GREEN))

    return 0 if (susp_c + hidden_c == 0) else 2


def cmd_serve(args: argparse.Namespace) -> int:
    run_server(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegohunter",
        description="Detect and extract hidden data from images and audio.",
        epilog="Modules: LSB, RS/SPA, palette, appended-data, WAV LSB, JPEG DCT, heatmaps, spectrograms, cracking, batch triage, web lab.",
    )
    parser.add_argument("--version", action="version", version=f"stegohunter {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Run full detection suite on a file")
    p_analyze.add_argument("file")
    p_analyze.set_defaults(func=cmd_analyze)

    # visualize
    p_viz = sub.add_parser("visualize", help="Generate spatial anomaly heatmap or bit-plane slices")
    p_viz.add_argument("file")
    p_viz.add_argument("-o", "--output", help="Output PNG path (default: <file>_heatmap.png)")
    p_viz.add_argument("-m", "--mode", choices=["heatmap", "bitplane", "grid"], default="heatmap",
                       help="Visualization mode (default: heatmap)")
    p_viz.add_argument("-b", "--bit", type=int, default=0, help="Bit plane for bitplane mode (0-7)")
    p_viz.add_argument("-c", "--channel", choices=["R", "G", "B", "all", "gray"], default="all",
                       help="Color channel (default: all)")
    p_viz.add_argument("--block-size", type=int, default=16, help="Block window size in pixels for heatmap")
    p_viz.add_argument("--alpha", type=float, default=0.5,
                       help="Heatmap overlay blend alpha: 0.0=heatmap only, 1.0=original only, 0.5=half blend")
    p_viz.set_defaults(func=cmd_visualize)

    # spectrogram
    p_spec = sub.add_parser("spectrogram", help="Generate audio frequency waterfall spectrogram")
    p_spec.add_argument("file", help="Audio file (WAV)")
    p_spec.add_argument("-o", "--output", help="Output PNG path (default: <file>_spectrogram.png)")
    p_spec.add_argument("--colormap", choices=["inferno", "viridis", "cyber", "grayscale"], default="inferno",
                        help="Colormap scheme (default: inferno)")
    p_spec.add_argument("--fft", type=int, default=1024, help="FFT window size (default: 1024)")
    p_spec.add_argument("--width", type=int, default=1200, help="Output image width")
    p_spec.add_argument("--height", type=int, default=600, help="Output image height")
    p_spec.set_defaults(func=cmd_spectrogram)

    # crack
    p_crack = sub.add_parser("crack", help="Dictionary attack on encrypted/keyed stego carriers")
    p_crack.add_argument("file", help="Target stego file")
    p_crack.add_argument("-w", "--wordlist", help="Wordlist text file (default: built-in wordlist)")
    p_crack.add_argument("-o", "--output", help="Output path for decrypted payload")
    p_crack.add_argument("--workers", type=int, default=8, help="Number of worker threads (default: 8)")
    p_crack.set_defaults(func=cmd_crack)

    # triage
    p_tri = sub.add_parser("triage", help="Batch triage an entire directory of files")
    p_tri.add_argument("directory", help="Target directory to inspect")
    p_tri.add_argument("-r", "--recursive", action="store_true", help="Recursively inspect subdirectories")
    p_tri.add_argument("--workers", type=int, default=4, help="Worker threads (default: 4)")
    p_tri.add_argument("--html", help="Path to generate standalone forensic HTML report")
    p_tri.add_argument("--json", help="Path to save JSON findings")
    p_tri.set_defaults(func=cmd_triage)

    # serve
    p_srv = sub.add_parser("serve", help="Launch interactive browser UI / StegSolve web lab")
    p_srv.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    p_srv.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    p_srv.add_argument("--no-browser", action="store_true", help="Do not automatically open web browser")
    p_srv.set_defaults(func=cmd_serve)

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

    p_rs_d = sub.add_parser("rs", help="Run RS and Sample Pair Analysis (embedding rate percentage)")
    p_rs_d.add_argument("file")
    p_rs_d.set_defaults(func=lambda a: _dump_json(analyze_rs(a.file)))

    p_meta_d = sub.add_parser("metadata", help="Run EXIF and PNG chunk metadata analysis")
    p_meta_d.add_argument("file")
    p_meta_d.set_defaults(func=lambda a: _dump_json(analyze_metadata(a.file)))

    p_dct_d = sub.add_parser("dct", help="Run JPEG DCT frequency domain analysis")
    p_dct_d.add_argument("file")
    p_dct_d.set_defaults(func=lambda a: _dump_json(analyze_jpeg_dct(a.file)))

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
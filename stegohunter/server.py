"""Interactive Browser UI and Local Web Server for StegoHunter."""

from __future__ import annotations

import base64
import http.server
import io
import json
import os
import socketserver
import tempfile
import threading
import webbrowser
from typing import Optional

from PIL import Image

from .extractors.appended import extract_appended_data
from .extractors.lsb import extract_lsb_message
from .orchestrator import full_analyze, is_audio, is_image
from .visualizer import extract_bit_plane, generate_bitplane_grid, generate_spatial_heatmap


def _image_to_base64_png(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>StegoHunter — Interactive Forensics Lab</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text: #f3f4f6;
      --text-dim: #9ca3af;
      --accent: #38bdf8;
      --green: #22c55e;
      --yellow: #f59e0b;
      --red: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand h1 {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }
    .brand p {
      font-size: 13px;
      color: var(--text-dim);
    }
    .dropzone {
      border: 2px dashed #374151;
      border-radius: 10px;
      background: var(--card-bg);
      padding: 36px 20px;
      text-align: center;
      cursor: pointer;
      margin-bottom: 24px;
      transition: all 0.2s;
    }
    .dropzone:hover, .dropzone.dragover {
      border-color: var(--accent);
      background: rgba(56, 189, 248, 0.05);
    }
    .dropzone p {
      font-size: 15px;
      font-weight: 500;
      color: var(--text);
    }
    .dropzone span {
      font-size: 13px;
      color: var(--text-dim);
    }
    .dashboard {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }
    @media (max-width: 900px) {
      .dashboard { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
    }
    .panel-title {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .viewer-box {
      background: #000;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      min-height: 320px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 16px;
      overflow: hidden;
      position: relative;
    }
    .viewer-box img {
      max-width: 100%;
      max-height: 480px;
      object-fit: contain;
    }
    .controls-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 12px;
    }
    .btn-plane {
      background: #1f2937;
      border: 1px solid #374151;
      color: var(--text);
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      cursor: pointer;
      font-weight: 500;
    }
    .btn-plane.active, .btn-plane:hover {
      background: var(--accent);
      color: #000;
      border-color: var(--accent);
    }
    .slider-row {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 13px;
      color: var(--text-dim);
      margin-top: 8px;
    }
    .slider-row input { flex: 1; }
    .badge {
      font-size: 12px;
      font-weight: 600;
      padding: 3px 8px;
      border-radius: 4px;
    }
    .badge-clean { background: rgba(34, 197, 94, 0.15); color: var(--green); border: 1px solid rgba(34, 197, 94, 0.3); }
    .badge-suspicious { background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-hidden { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); }
    .findings-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 20px;
      max-height: 380px;
      overflow-y: auto;
    }
    .mod-block {
      background: #1e293b;
      border-radius: 6px;
      padding: 12px;
      font-size: 13px;
    }
    .mod-header {
      display: flex;
      justify-content: space-between;
      font-weight: 600;
      margin-bottom: 6px;
    }
    .payload-box {
      background: #000;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 12px;
      font-family: monospace;
      font-size: 12px;
      max-height: 140px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
      color: #38bdf8;
    }
    .btn-download {
      margin-top: 10px;
      background: var(--accent);
      color: #000;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>StegoHunter Web Lab</h1>
      <p>Interactive Bit-Plane Slicing, Spatial Heatmaps, and Forensics</p>
    </div>
  </header>

  <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
    <input type="file" id="fileInput" style="display: none;" onchange="handleFileSelect(this.files[0])">
    <p>Drop image or audio file here to inspect</p>
    <span>Supports PNG, JPG, GIF, BMP, WEBP, WAV</span>
  </div>

  <div class="dashboard" id="dashboard" style="display: none;">
    <!-- Visual / Spectrogram Panel -->
    <div class="panel">
      <div class="panel-title">
        <span>StegSolve & Anomaly Visualizer</span>
        <span id="activePlaneLabel" style="font-size: 12px; color: var(--accent);">Normal</span>
      </div>
      <div class="viewer-box">
        <img id="viewerImg" src="" alt="Artifact Viewer">
      </div>
      <div class="controls-grid" id="planeControls">
        <button class="btn-plane active" onclick="setPlane('normal')">Normal</button>
        <button class="btn-plane" onclick="setPlane('heatmap')">Heatmap</button>
        <button class="btn-plane" onclick="setPlane('grid')">8-Bit Grid</button>
        <button class="btn-plane" onclick="setPlane('invert')">Invert</button>
        <button class="btn-plane" onclick="setPlane('r0')">R-0 (LSB)</button>
        <button class="btn-plane" onclick="setPlane('g0')">G-0 (LSB)</button>
        <button class="btn-plane" onclick="setPlane('b0')">B-0 (LSB)</button>
        <button class="btn-plane" onclick="setPlane('r7')">R-7 (MSB)</button>
        <button class="btn-plane" onclick="setPlane('g7')">G-7 (MSB)</button>
        <button class="btn-plane" onclick="setPlane('b7')">B-7 (MSB)</button>
      </div>
      <div class="slider-row" id="opacityRow">
        <span>Heatmap Opacity:</span>
        <input type="range" id="opacitySlider" min="0" max="100" value="50" oninput="updateOpacity(this.value)">
        <span id="opacityVal">50%</span>
      </div>
    </div>

    <!-- Forensic Readout Panel -->
    <div class="panel">
      <div class="panel-title">
        <span id="targetFileName">Target Analysis</span>
        <span id="verdictBadge" class="badge">CLEAN</span>
      </div>
      <div class="findings-list" id="findingsList">
        <!-- Dynamic module blocks -->
      </div>

      <div class="panel-title" style="margin-top: 16px;">
        <span>Recovered Payload</span>
      </div>
      <div class="payload-box" id="payloadPreview">No extracted payload yet.</div>
      <button class="btn-download" id="downloadBtn" style="display: none;" onclick="downloadExtracted()">Download Payload File</button>
    </div>
  </div>

  <script>
    let activeAnalysis = null;
    let extractedBlobUrl = null;
    let extractedFileName = "extracted_payload.bin";

    const dropzone = document.getElementById('dropzone');
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
      }
    });

    function handleFileSelect(file) {
      if (!file) return;
      document.getElementById('targetFileName').innerText = file.name;
      const reader = new FileReader();
      reader.onload = async () => {
        const b64 = reader.result.split(',')[1];
        dropzone.querySelector('p').innerText = "Analyzing " + file.name + "...";
        try {
          const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: file.name, data: b64 })
          });
          const data = await resp.json();
          renderAnalysis(data);
        } catch (err) {
          alert('Analysis failed: ' + err);
        } finally {
          dropzone.querySelector('p').innerText = "Drop image or audio file here to inspect";
        }
      };
      reader.readAsDataURL(file);
    }

    function renderAnalysis(data) {
      activeAnalysis = data;
      document.getElementById('dashboard').style.display = 'grid';

      // Set viewer image
      document.getElementById('viewerImg').src = 'data:image/png;base64,' + (data.preview_base64 || data.normal_base64);

      // Set verdict badge
      const badge = document.getElementById('verdictBadge');
      badge.innerText = data.verdict;
      badge.className = 'badge ' + (data.verdict === 'CLEAN' ? 'badge-clean' : data.verdict === 'HIDDEN DATA LIKELY' ? 'badge-hidden' : 'badge-suspicious');

      // Findings list
      const findingsList = document.getElementById('findingsList');
      findingsList.innerHTML = '';
      (data.findings || []).forEach(f => {
        const mod = f.module || 'Unknown';
        const isSusp = f.suspicious || f.appended;
        const reasons = (f.reasons || f.details || []).map(r => '• ' + r).join('<br>') || f.note || 'Nominal readings';

        const div = document.createElement('div');
        div.className = 'mod-block';
        div.innerHTML = `
          <div class="mod-header">
            <span>${mod.toUpperCase()}</span>
            <span style="color: ${isSusp ? 'var(--red)' : 'var(--green)'};">${isSusp ? 'SUSPICIOUS' : 'CLEAN'}</span>
          </div>
          <div style="color: var(--text-dim); line-height: 1.4;">${reasons}</div>
        `;
        findingsList.appendChild(div);
      });

      // Extracted payload
      const preview = document.getElementById('payloadPreview');
      const dlBtn = document.getElementById('downloadBtn');
      if (data.extracted_base64) {
        const byteChars = atob(data.extracted_base64);
        let previewStr = '';
        for (let i = 0; i < Math.min(byteChars.length, 300); i++) {
          const code = byteChars.charCodeAt(i);
          previewStr += (code >= 32 && code < 127) ? byteChars[i] : '.';
        }
        preview.innerText = previewStr;

        const byteNumbers = new Array(byteChars.length);
        for (let i = 0; i < byteChars.length; i++) byteNumbers[i] = byteChars.charCodeAt(i);
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: 'application/octet-stream' });
        extractedBlobUrl = URL.createObjectURL(blob);
        dlBtn.style.display = 'inline-block';
      } else {
        preview.innerText = 'No extracted payload recovered.';
        dlBtn.style.display = 'none';
      }
    }

    function setPlane(planeKey) {
      if (!activeAnalysis || !activeAnalysis.planes) return;
      document.querySelectorAll('.btn-plane').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('activePlaneLabel').innerText = event.target.innerText;

      const img = document.getElementById('viewerImg');
      if (activeAnalysis.planes[planeKey]) {
        img.src = 'data:image/png;base64,' + activeAnalysis.planes[planeKey];
      }
    }

    function updateOpacity(val) {
      document.getElementById('opacityVal').innerText = val + '%';
      if (activeAnalysis && activeAnalysis.planes && activeAnalysis.planes.heatmap) {
        document.getElementById('viewerImg').style.opacity = val / 100.0;
      }
    }

    function downloadExtracted() {
      if (!extractedBlobUrl) return;
      const a = document.createElement('a');
      a.href = extractedBlobUrl;
      a.download = extractedFileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  </script>
</body>
</html>
"""


class StegoServerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/api/analyze":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                payload = json.loads(body.decode("utf-8"))
                filename = payload.get("filename", "upload.bin")
                raw_bytes = base64.b64decode(payload["data"])

                # Save to temporary file for orchestrator
                ext = os.path.splitext(filename)[1].lower()
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                    tmp.write(raw_bytes)
                    tmp_path = tmp.name

                try:
                    report = full_analyze(tmp_path)
                    planes: dict[str, str] = {}
                    preview_b64: Optional[str] = None

                    if is_image(tmp_path):
                        # Generate normal image
                        im = Image.open(tmp_path).convert("RGB")
                        planes["normal"] = _image_to_base64_png(im)
                        preview_b64 = planes["normal"]

                        # Inverted
                        inv = Image.eval(im, lambda x: 255 - x)
                        planes["invert"] = _image_to_base64_png(inv)

                        # Heatmap
                        heat_img, _ = generate_spatial_heatmap(tmp_path, alpha=0.0)
                        planes["heatmap"] = _image_to_base64_png(heat_img)

                        # Grid
                        grid_img = generate_bitplane_grid(tmp_path, channel="R")
                        planes["grid"] = _image_to_base64_png(grid_img)

                        # Single bit planes (R, G, B at 0 and 7)
                        for ch in ("R", "G", "B"):
                            p0 = extract_bit_plane(tmp_path, channel=ch, bit=0)
                            p7 = extract_bit_plane(tmp_path, channel=ch, bit=7)
                            planes[f"{ch.lower()}0"] = _image_to_base64_png(p0)
                            planes[f"{ch.lower()}7"] = _image_to_base64_png(p7)

                        # Attempt LSB extraction
                        lsb_res = extract_lsb_message(tmp_path, max_bytes=8192)
                        if lsb_res.get("length", 0) > 0:
                            report["extracted_base64"] = base64.b64encode(lsb_res["extracted"]).decode("ascii")

                    elif is_audio(tmp_path):
                        from .audio.spectrogram import generate_spectrogram
                        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as spec_tmp:
                            spec_out = spec_tmp.name
                        try:
                            spec_img, _ = generate_spectrogram(tmp_path, output_path=spec_out)
                            preview_b64 = _image_to_base64_png(spec_img)
                            planes["normal"] = preview_b64
                        finally:
                            if os.path.exists(spec_out):
                                os.unlink(spec_out)

                    # Check appended payload
                    app_res = extract_appended_data(tmp_path)
                    if app_res.get("appended") and not report.get("extracted_base64"):
                        report["extracted_base64"] = base64.b64encode(app_res["extracted"][:8192]).decode("ascii")

                    report["preview_base64"] = preview_b64
                    report["planes"] = planes

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(report, default=str).encode("utf-8"))

                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy HTTP request stdout logs
        pass


def run_server(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True) -> None:
    """Launch local StegoHunter interactive browser UI."""
    server_address = (host, port)
    httpd = socketserver.TCPServer(server_address, StegoServerHandler)
    url = f"http://{host}:{port}/"
    print(f"[ARCHIVE: ONLINE — StegoHunter Web Lab]")
    print(f"  serving at:  {url}")
    print(f"  press Ctrl+C to terminate server")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] StegoHunter server stopped.")
    finally:
        httpd.server_close()

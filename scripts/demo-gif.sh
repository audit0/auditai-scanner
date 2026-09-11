#!/usr/bin/env bash
# Records demo.gif for the README: vhs renders the terminal frames, ffmpeg assembles them.
# Requires `brew install vhs` (brings ttyd and ffmpeg). Run from the repository root.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf demo-frames.png
npm install --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1   # links node_modules/.bin/auditai-scan, the workspace bin: same code as the npm package
vhs demo.tape >/dev/null
ffmpeg -y -v error \
  -framerate 50 -i demo-frames.png/frame-text-%05d.png \
  -framerate 50 -i demo-frames.png/frame-cursor-%05d.png \
  -filter_complex "[0][1]overlay[v];[v]fps=15,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=5" \
  demo.gif
rm -rf demo-frames.png
ls -la demo.gif

#!/bin/sh
# Render PNG images from the SVG sources in assets/src. Requires rsvg-convert (brew install librsvg).
set -eu
cd "$(dirname "$0")/.."
command -v rsvg-convert >/dev/null || { echo "rsvg-convert not found (brew install librsvg)" >&2; exit 1; }
out=assets
# GitHub social preview: 1280x640 (2:1)
rsvg-convert -w 1280 -h 640 assets/src/hero.svg -o "$out/social-preview.png"
# README hero at 2x retina width
rsvg-convert -w 1600 assets/src/hero.svg -o "$out/hero.png"
# Open Graph / Twitter card: 1200x630, hero re-framed with a taller viewBox
tmp=$(mktemp -t og.XXXXXX)
sed 's/viewBox="0 0 1600 800" width="1600" height="800"/viewBox="0 -20 1600 840" width="1600" height="840"/' assets/src/hero.svg > "$tmp"
rsvg-convert -w 1200 -h 630 "$tmp" -o "$out/og-image.png"
rm -f "$tmp"
rsvg-convert -w 1600 assets/src/pipeline.svg -o "$out/pipeline.png"
rsvg-convert -w 1400 assets/src/lint.svg -o "$out/lint.png"
cp "$out/og-image.png" site/og-image.png
echo "rendered:"; ls -l "$out"/*.png

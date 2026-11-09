#!/usr/bin/env python3
import sys
import subprocess
from PIL import Image

def capture(output_path, x=224, y=75, w=1280, h=852):
    tmp_path = "/tmp/full_screen_cap.png"
    subprocess.run(["screencapture", "-x", tmp_path], check=True)
    im = Image.open(tmp_path)
    scale = im.width / 1728.0 if im.width > 2000 else 1.0
    
    box = (
        int(x * scale),
        int(y * scale),
        int((x + w) * scale),
        int((y + h) * scale),
    )
    cropped = im.crop(box)
    cropped.save(output_path)
    print(f"Captured window to {output_path} ({cropped.size})")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/cropped.png"
    capture(out)

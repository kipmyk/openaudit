#!/usr/bin/env python3
"""
Generates the native AppIcon.icns for OpenAudit Desktop using Pillow and iconutil.
Adheres strictly to the Mike Design System: crisp monochrome / deep slate canvas,
geometric shield silhouette, high-density SVG-inspired line rendering.
"""

import os
import subprocess
import shutil
from PIL import Image, ImageDraw

def create_base_icon(size=1024):
    # Canvas with rounded rect squircle background
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Base background: Deep refined slate (#0f172a) squircle
    pad = int(size * 0.08)
    radius = int(size * 0.22)
    bg_rect = [pad, pad, size - pad, size - pad]
    draw.rounded_rectangle(bg_rect, radius=radius, fill=(15, 23, 42, 255), outline=(51, 65, 85, 255), width=max(2, int(size * 0.015)))

    # Inner subtle glow ring
    inner_pad = pad + int(size * 0.03)
    inner_radius = int(radius * 0.85)
    draw.rounded_rectangle([inner_pad, inner_pad, size - inner_pad, size - inner_pad], radius=inner_radius, outline=(30, 41, 59, 255), width=max(1, int(size * 0.008)))

    # Shield geometry
    cx = size // 2
    top_y = int(size * 0.24)
    shoulder_y = int(size * 0.38)
    bottom_y = int(size * 0.78)
    half_w = int(size * 0.24)
    stroke_w = max(4, int(size * 0.032))

    # Points for a crisp modern shield
    # Top-left, top-right, right-shoulder, bottom-point, left-shoulder
    shield_pts = [
        (cx, top_y),
        (cx + half_w, int(top_y + size * 0.05)),
        (cx + half_w, shoulder_y + int(size * 0.12)),
        (cx, bottom_y),
        (cx - half_w, shoulder_y + int(size * 0.12)),
        (cx - half_w, int(top_y + size * 0.05)),
    ]

    # Draw shield outline in crisp accent blue / light slate
    draw.polygon(shield_pts, outline=(59, 130, 246, 255), width=stroke_w)

    # Inner checkmark / keyhole crosshair in crisp white/slate
    check_pts = [
        (cx - int(half_w * 0.45), int(size * 0.51)),
        (cx - int(half_w * 0.1), int(size * 0.61)),
        (cx + int(half_w * 0.5), int(size * 0.42))
    ]
    draw.line(check_pts, fill=(248, 250, 252, 255), width=int(stroke_w * 1.1), joint="curve")

    return img

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_root = os.path.dirname(script_dir)
    macos_pkg_dir = os.path.join(workspace_root, "packaging", "macos")
    os.makedirs(macos_pkg_dir, exist_ok=True)

    iconset_dir = os.path.join(macos_pkg_dir, "AppIcon.iconset")
    if os.path.exists(iconset_dir):
        shutil.rmtree(iconset_dir)
    os.makedirs(iconset_dir, exist_ok=True)

    base = create_base_icon(1024)

    # Standard macOS icon sizes and scale factors
    sizes = [
        (16, 1), (16, 2),
        (32, 1), (32, 2),
        (128, 1), (128, 2),
        (256, 1), (256, 2),
        (512, 1), (512, 2)
    ]

    for pt_size, scale in sizes:
        px = pt_size * scale
        resized = base.resize((px, px), Image.Resampling.LANCZOS)
        name = f"icon_{pt_size}x{pt_size}.png" if scale == 1 else f"icon_{pt_size}x{pt_size}@2x.png"
        resized.save(os.path.join(iconset_dir, name))

    # Convert to .icns using macOS iconutil
    icns_path = os.path.join(macos_pkg_dir, "AppIcon.icns")
    cmd = ["iconutil", "-c", "icns", iconset_dir, "-o", icns_path]
    subprocess.check_call(cmd)
    shutil.rmtree(iconset_dir)
    print(f"[+] Generated native macOS icon: {icns_path} ({os.path.getsize(icns_path)} bytes)")

if __name__ == "__main__":
    main()


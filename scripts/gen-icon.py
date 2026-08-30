#!/usr/bin/env python3
"""Generate the nzinga brand icon (PNG + ICO).

Brand: NZINGA — Brand Amber #FFB000.
Draws a stylized crown above a bold "N" on a rounded amber tile.
"""

from PIL import Image, ImageDraw


def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


AMBER = hex_to_rgb("FFB000")
AMBER_DARK = hex_to_rgb("C97A00")
CREAM = hex_to_rgb("FFF3DC")

SIZE = 512
MARGIN = 40
TILE = (SIZE - 2 * MARGIN)

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# rounded tile background
x0, y0, x1, y1 = MARGIN, MARGIN, SIZE - MARGIN, SIZE - MARGIN
r = 96
d.rounded_rectangle([x0, y0, x1, y1], radius=r, fill=AMBER)

# crown: three spikes over a joined base
base_y = MARGIN + TILE * 0.42
crown_w = TILE * 0.56
c_x = SIZE // 2
spike_w = TILE * 0.10
h1 = TILE * 0.20
h2 = TILE * 0.15
h3 = TILE * 0.13
vertical = [
    (c_x - crown_w / 2, base_y - h1),
    (c_x, base_y - h3),
    (c_x + crown_w / 2 - spike_w, base_y - h2),
]
for (cx, top) in vertical:
    d.rounded_rectangle([cx, top, cx + spike_w, base_y], radius=8, fill=CREAM)
# crown base bar
d.rounded_rectangle(
    [c_x - crown_w / 2 - TILE * 0.02, base_y - TILE * 0.05,
     c_x + crown_w / 2 + TILE * 0.02, base_y + TILE * 0.045],
    radius=10, fill=AMBER_DARK)

# bold "N" beneath the crown
n_left = c_x - TILE * 0.26
n_right = c_x + TILE * 0.26
n_top = base_y + TILE * 0.14
n_bot = n_top + TILE * 0.34
bar_w = TILE * 0.085
# left vertical, diagonal, right vertical
d.rounded_rectangle([n_left, n_top, n_left + bar_w, n_bot], radius=6, fill=CREAM)
d.rounded_rectangle([n_right - bar_w, n_top, n_right, n_bot], radius=6, fill=CREAM)
d.polygon(
    [
        (n_left + bar_w, n_top),
        (n_right - bar_w, n_top),
        (n_right, n_top + bar_w),
        (n_right, n_top + TILE * 0.10),
        (n_left + bar_w, n_bot),
        (n_left, n_bot - TILE * 0.08),
    ],
    fill=CREAM,
)

img.save("/home/wsuits6/WORK/QYVORA/products/qyvora-opensource-tools/qyvora-nzinga/assets/nzinga.png")
img.save("/home/wsuits6/WORK/QYVORA/products/qyvora-opensource-tools/qyvora-nzinga/assets/nzinga.ico", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
print("wrote icon")
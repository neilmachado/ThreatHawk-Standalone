"""Optional local terminal artwork, configured outside the distribution."""
import json
import os
from pathlib import Path
from rich.text import Text
from rich.style import Style


def show_logo(console):
    path = os.environ.get('THREATHAWK_LOGO')
    if not path or not console.is_terminal or not console.color_system:
        return
    try:
        file = Path(path)
        if file.stat().st_size > 100_000:
            return
        data = json.loads(file.read_text())
        width, height, pixels = data['width'], data['height'], data['pixels']
        if not (isinstance(width,int) and isinstance(height,int) and 1 <= width <= min(60,console.width) and 1 <= height <= 60 and len(pixels)==width*height):
            return
        if not all(len(p)==4 and all(isinstance(c,int) and 0<=c<=255 for c in p) for p in pixels):
            return
        def color(pixel):
            return '#%02x%02x%02x' % tuple(pixel[:3]) if pixel[3]>=128 else None
        for y in range(0,height,2):
            row=Text()
            for x in range(width):
                upper=color(pixels[y*width+x])
                lower=color(pixels[(y+1)*width+x]) if y+1<height else None
                if upper:
                    row.append('▀',Style(color=upper,bgcolor=lower))
                elif lower:
                    row.append('▄',Style(color=lower))
                else:
                    row.append(' ')
            console.print(row)
    except (OSError,ValueError,KeyError,TypeError):
        return

#!/usr/bin/env python3
"""Bundle VulnLab V5 into one offline HTML for sharing / review."""
from pathlib import Path
import re
R=Path(__file__).resolve().parents[1]
source=(R/'index.html').read_text(encoding='utf-8')
styles=(R/'styles.css').read_text(encoding='utf-8')
source=source.replace('<link rel="stylesheet" href="styles.css">','<style>'+styles+'</style>')
scripts=[]
for src in ('data/curated.js','data/reading-queue.js','data/feed-data.js','app.js'):
    script=(R/src).read_text(encoding='utf-8').replace('</script','<\\/script')
    tag=f'<script defer src="{src}"></script>'
    assert tag in source,src
    source=source.replace(tag,'')
    scripts.append('<script>\n'+script+'\n</script>')
# Inline scripts execute immediately. Keep them AFTER #app, unlike defer external scripts.
source=source.replace('</body>', '\n'.join(scripts)+'\n</body>')
source=source.replace('<title>VulnLab V5', '<title>VulnLab V5 (Offline)')
out=Path('/mnt/data/VulnLab-V5-Open.html')
out.write_text(source,encoding='utf-8')
print(out, f'{out.stat().st_size:,} bytes')

import re,glob,collections,sys
import os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ORDER=['HTTPとWebの基礎','OAuth 2.0の基本','OpenID Connect','トークンとJOSE','暗号','クライアントと認証','攻撃と防御','ブラウザとアプリ','拡張仕様','運用と周辺技術','標準化']
entries=[]  # (cat, ch, idx, term, text)
for f in sorted(glob.glob('src/glossary/ch*.md')):
    ch=int(re.search(r'ch(\d+)',f).group(1)); cat=None; cur=None
    for line in open(f):
        line=line.rstrip('\n')
        if line.startswith('## '): cat=line[3:].strip(); continue
        if line.startswith('- **'):
            cur=[cat,ch,len(entries),line]; entries.append(cur)
        elif line.startswith('  ') and cur and line.strip():
            cur[3]+= line.strip() if re.match(r'[　-鿿]', line.strip()) else ' '+line.strip()
        elif not line.strip(): cur=None
def key(t):
    m=re.match(r'- \*\*(.+?)\*\*',t); k=m.group(1) if m else t
    return re.sub(r'[\s`]','',k).lower()
seen={}; dups=[]
for e in entries:
    k=key(e[3])
    if k in seen: dups.append((seen[k],e)); continue
    seen[k]=e
bycat=collections.defaultdict(list)
for e in seen.values(): bycat[e[0]].append(e)
unknown=[c for c in bycat if c not in ORDER]
print('unknown cats',unknown, file=sys.stderr)
print('entries',len(entries),'unique',len(seen),'dups',len(dups), file=sys.stderr)
for a,b in dups: print(f'DUP ch{a[1]} vs ch{b[1]}: {a[3][:70]} || {b[3][:70]}', file=sys.stderr)
out=['---','title: 用語集','description: 本書で登場した技術用語の定義集。分野別に、初出の章へのリンク付きでまとめる。','sidebar:','  label: 用語集','---','',
'本書で定義した技術用語を分野別にまとめました。',
'括弧内は英語表記、末尾のリンクは初出の章です。各分野の中は初出の章の順に並べています。','']
for c in ORDER:
    if c not in bycat: continue
    out.append(f'## {c}'); out.append('')
    for e in sorted(bycat[c], key=lambda e:(e[1],e[2])): out.append(e[3])
    out.append('')
open('docs/appendix/glossary.md','w').write('\n'.join(out))

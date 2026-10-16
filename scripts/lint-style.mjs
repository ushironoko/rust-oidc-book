// STYLE.md のうち機械的に検出できる規則を docs/ と src/snippets/ に適用する。
// 使い方: node scripts/lint-style.mjs [file ...]
import { globSync, readFileSync } from 'node:fs';

const files =
  process.argv.length > 2
    ? process.argv.slice(2)
    : [...globSync('docs/**/*.md'), ...globSync('src/snippets/**/*.rs')];

const RULES = [
  [/—|――|─―/, 'ダッシュ'],
  [/[（）]/, '全角括弧'],
  [/あなた/, '読者を「あなた」と呼ぶ'],
  [/(^|[。、\s])(実は|さて|なんと|いよいよ|いきなり|ついに)/, '演出の語'],
  [/(はこうです|はこれです|注意を1つ|補足を\d+つ|種明かし|答え合わせ)/, '内容のない前置き'],
  [/(爆速|劇的|桁違い|面白い|強力な|美しい)/, '誇張・主観の評価語'],
  [/(罠|心臓部|処方箋|犯人|土台|橋渡し|素通り|殺到|骨格|流儀|儀式|作法|潮流|値段|高くつく|載せる|載る|食う|使い回|打ち手|手の空いた|勝手に|律儀に|黙って|賢く|素直に|大胆に)/, '使わない表現'],
  [/(一つ|ひとつ|二つ|ふたつ|三つ|みっつ)/, '個数は算用数字'],
];

let count = 0;
for (const file of files) {
  const lines = readFileSync(file, 'utf8').split('\n');
  let inFence = false;
  lines.forEach((line, i) => {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
    const isCode = file.endsWith('.rs');
    const prose = !inFence && !line.startsWith('>');
    for (const [re, name] of RULES) {
      if (name === '全角括弧' || name === 'ダッシュ' ? true : prose || isCode) {
        if (re.test(line)) {
          console.log(`${file}:${i + 1}: ${name}: ${line.trim().slice(0, 90)}`);
          count++;
        }
      }
    }
  });
}
// 強調が成立したかは CommonMark+cjkEmphasis の判定次第なので、生成HTMLで確かめる
for (const html of globSync('dist/**/*.html')) {
  const text = readFileSync(html, 'utf8')
    .replace(/<(pre|code|script|style)[\s\S]*?<\/\1>/g, '')
    .replace(/<[^>]+>/g, '');
  const hits = text.match(/.{0,20}\*\*.{0,20}/g);
  if (hits) {
    for (const h of hits) console.log(`${html}: 強調記号が文字のまま: ${h.trim()}`);
    count += hits.length;
  }
}
console.log(`[lint-style] ${count} 件`);
process.exit(count > 0 ? 1 : 0);

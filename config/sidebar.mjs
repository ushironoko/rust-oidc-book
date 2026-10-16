// docs/ の frontmatter (sidebar.label / title) から ox-content の
// テーマ sidebar 構成を生成する。順序はファイル名の数字プレフィックスに従う。
import { globSync, readFileSync } from 'node:fs';

const GROUPS = [
  { text: 'Part I: Webの認証と認可', dir: 'web-auth' },
  { text: 'Part II: OpenID Connectを知る', dir: 'oidc' },
  { text: 'Part III: RustでOIDCを動かす', dir: 'rust-impl' },
  { text: 'Part IV: OAuth 2.0の深層', dir: 'oauth-deep' },
  { text: 'Part V: OpenID Connectの深層', dir: 'oidc-deep' },
  { text: 'Part VI: セキュリティの深層', dir: 'security' },
  { text: 'Part VII: 運用と周辺技術', dir: 'practice' },
  { text: '付録', dir: 'appendix' },
];

function frontmatterOf(file) {
  const src = readFileSync(file, 'utf8');
  const m = src.match(/^---\n([\s\S]*?)\n---/);
  if (!m) return {};
  const fm = {};
  const title = m[1].match(/^title:\s*(.+)$/m);
  if (title) fm.title = title[1].trim().replace(/^['"]|['"]$/g, '');
  const label = m[1].match(/^sidebar:\n\s+label:\s*(.+)$/m);
  if (label) fm.label = label[1].trim().replace(/^['"]|['"]$/g, '');
  return fm;
}

export function buildSidebar() {
  const sidebar = [
    { text: 'はじめに', items: [{ text: 'はじめに', link: '/index.md' }] },
  ];
  for (const group of GROUPS) {
    const files = globSync(`docs/${group.dir}/*.md`).sort();
    sidebar.push({
      text: group.text,
      items: files.map((file) => {
        const fm = frontmatterOf(file);
        return {
          text: fm.label ?? fm.title ?? file,
          link: file.replace(/^docs/, '').replace(/\\/g, '/'),
        };
      }),
    });
  }
  return sidebar;
}

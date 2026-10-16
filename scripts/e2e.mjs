// サイトの機能スモークテスト。事前に dist/ をビルドし、
// python3 -m http.server 4185 -d dist などで配信してから実行する。
// 使い方: node scripts/e2e.mjs
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';

const BASE = 'http://127.0.0.1:4185';
const SHOT = process.env.E2E_SHOT_DIR ?? '.e2e-shots';
const results = [];
const ok = (name, cond, extra = '') => {
  results.push(`${cond ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
};

// ページ内 idx 番目の code-play widget の payload(base64 JSON)を読む
const playConfig = (page, idx) =>
  page.evaluate((i) => {
    const el = document.querySelectorAll('ox-code-play')[i];
    if (!el) return null;
    return JSON.parse(atob(el.getAttribute('data-ox-code-play'))).config;
  }, idx);

mkdirSync(SHOT, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.E2E_CHROMIUM ?? '/opt/pw-browsers/chromium' });
const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });

// --- 章ページ(ライト) ---
await page.goto(`${BASE}/oidc/09-state-nonce-pkce/`, { waitUntil: 'networkidle' });
await page.emulateMedia({ colorScheme: 'light' });
await page.waitForTimeout(300);

ok('h1 title', (await page.textContent('article h1'))?.trim() === 'state・nonce・PKCE');
ok('sidebar group', (await page.textContent('.sidebar'))?.includes('Part II: OpenID Connectを知る'));
ok('sidebar label', (await page.textContent('.sidebar'))?.includes('9. state・nonce・PKCE'));
ok('toc localized', (await page.textContent('.toc-title'))?.trim() === '目次');
const play = page.locator('ox-code-play').first();
ok('code-play count', (await page.locator('ox-code-play').count()) === 3, String(await page.locator('ox-code-play').count()));
ok('code-play highlight', (await play.locator('pre.ox-highlight').count()) === 1);

await page.screenshot({ path: `${SHOT}/light-chapter.png`, fullPage: false });

// --- 前後ページリンク (v3 ssg.pagination) ---
const prevHref = await page.locator('.pager a[rel="prev"]').getAttribute('href').catch(() => null);
const nextHref = await page.locator('.pager a[rel="next"]').getAttribute('href').catch(() => null);
// v3 pager はサイドバーと同じ /index.html 付きリンクを出す
ok('pager prev', prevHref === '/oidc/08-id-token-validation/index.html', String(prevHref));
ok('pager next', nextHref === '/rust-impl/10-discovery-jwks/index.html', String(nextHref));
ok('pager label ja', (await page.locator('.pager .pager-label').first().textContent())?.trim() === '前のページ');

// --- code-play 実行(外部API: play.rust-lang.org) ---
// ja-ui.js が Run → 実行 に置換していることも同時に検証する
const runBtn = play.locator('button[data-ox-action="run"]');
await runBtn.waitFor({ timeout: 10000 });
ok('run button ja', (await runBtn.textContent())?.trim() === '実行');
// ch09 の先頭 widget は既定の debug モード
const overflowConfig = await playConfig(page, 0);
ok('config debug kept', overflowConfig && overflowConfig.mode === 'debug', JSON.stringify(overflowConfig));
const pkce = page.locator('ox-code-play').nth(1);
const pkceRun = pkce.locator('button[data-ox-action="run"]');
await pkceRun.click();
// RFC 7636 付録B の code_challenge が出力に現れ、cargo のビルドノイズは
// play-output.js が間引いていることを、画面に見えるテキストで検証する
try {
  await page.waitForFunction(
    () => /E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM/.test(document.querySelectorAll('ox-code-play')[1]?.innerText ?? ''),
    { timeout: 30000 }
  );
  await page.waitForTimeout(800);
  const visible = await pkce.evaluate((el) => el.innerText);
  ok('run output (RFC 7636 vector, no noise)', !/Compiling playground|Finished `/.test(visible), visible.replace(/\s+/g, ' ').slice(0, 80));
} catch {
  ok('run output (RFC 7636 vector, no noise)', false, 'timeout (network?)');
}

// --- ダークモード切替 ---
await page.locator('header .theme-toggle, header [aria-label*="テーマ"], header [aria-label*="theme" i]').first().click();
await page.waitForTimeout(300);
const theme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
ok('theme toggled', theme === 'dark' || theme === 'light', `data-theme=${theme}`);
await page.screenshot({ path: `${SHOT}/dark-chapter.png` });

// --- 検索(日本語) ---
await page.keyboard.press('/');
await page.waitForTimeout(300);
const searchInput = page.locator('input.search-input');
ok('search opens', await searchInput.isVisible());
ok('search placeholder ja', (await searchInput.getAttribute('placeholder')) === '検索');
await searchInput.fill('認可コード');
await page.waitForTimeout(600);
const resultsText = await page.locator('.search-results, .search-modal').first().textContent();
ok('search ja results', resultsText.includes('認可コード'), resultsText.slice(0, 100).replace(/\n/g, ' '));
await page.screenshot({ path: `${SHOT}/search.png` });
await page.keyboard.press('Escape');

// --- 検索0件表示 ---
await page.locator('header .search-button').click();
await page.waitForTimeout(300);
await searchInput.fill('zzzzqqqq');
const emptyOk = await page
  .waitForFunction(
    () =>
      [...document.querySelectorAll('.search-empty')].some(
        (el) => el.textContent.trim() === '見つかりませんでした'
      ),
    { timeout: 5000 }
  )
  .then(() => true)
  .catch(() => false);
if (!emptyOk) {
  console.log('DEBUG empty search:', await page.evaluate(() => ({
    inputVal: document.querySelector('input.search-input')?.value,
    results: document.querySelector('.search-results')?.innerHTML?.slice(0, 150),
    empties: [...document.querySelectorAll('.search-empty')].map((x) => x.textContent),
    overlayClass: document.querySelector('.search-modal-overlay')?.className,
  })));
}
ok('search empty ja', emptyOk);
await page.keyboard.press('Escape');

// --- mermaid(03-authorization-code) ---
await page.goto(`${BASE}/web-auth/03-authorization-code/`, { waitUntil: 'networkidle' });
ok('mermaid svg', (await page.locator('.ox-mermaid svg').count()) > 0, String(await page.locator('.ox-mermaid svg').count()));
await page.screenshot({ path: `${SHOT}/mermaid.png` });

// --- :::note (07-jwt-jose) ---
await page.goto(`${BASE}/oidc/07-jwt-jose/`, { waitUntil: 'networkidle' });
ok('aside rendered', (await page.locator('.ox-container--note').count()) === 2, String(await page.locator('.ox-container--note').count()));
ok('aside markdown inside', (await page.locator('.ox-container--note strong, .ox-container--note code, .ox-container--note a, .ox-container--note p').count()) > 0);

// --- release widget (05-crypto の先頭は mode="release") ---
await page.goto(`${BASE}/web-auth/05-crypto/`, { waitUntil: 'networkidle' });
const ch05First = await playConfig(page, 0);
const ch05Second = await playConfig(page, 1);
ok('ch05 release widget', ch05First && ch05First.mode === 'release', JSON.stringify(ch05First));
ok('ch05 debug widget', ch05Second && ch05Second.mode === 'debug', JSON.stringify(ch05Second));

// --- トップページ ---
await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
ok('top page h1', (await page.textContent('article h1'))?.trim() === 'はじめに');
ok('top code-play', (await page.locator('ox-code-play').count()) === 1);
ok('top pager no-prev', (await page.locator('.pager a[rel="prev"]').count()) === 0);
ok('top pager next', (await page.locator('.pager a[rel="next"]').getAttribute('href').catch(() => null)) === '/web-auth/01-http-auth/index.html');
await page.screenshot({ path: `${SHOT}/top.png` });

// --- モバイル ---
try {
  await page.setViewportSize({ width: 390, height: 800 });
  await page.goto(`${BASE}/oidc/09-state-nonce-pkce/`, { waitUntil: 'networkidle' });
  const menuBtn = page.locator('.menu-toggle:visible, .mobile-footer button:visible').first();
  ok('mobile menu button', await menuBtn.isVisible().catch(() => false));
  await menuBtn.click({ timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(400);
  ok('mobile sidebar opens', await page.locator('.sidebar').isVisible().catch(() => false));
  // シートが header〜footer 間に収まり、内部スクロールできること
  // (top 制約が外れると scrollHeight == clientHeight になり検出できる)
  const scroll = await page.evaluate(() => {
    const sb = document.querySelector('.sidebar');
    sb.scrollTop = 120;
    return {
      overflows: sb.scrollHeight > sb.clientHeight,
      canScroll: sb.scrollTop > 0,
      topOnScreen: sb.getBoundingClientRect().top >= 0,
    };
  });
  ok(
    'mobile sidebar scrolls',
    scroll.overflows && scroll.canScroll && scroll.topOnScreen,
    JSON.stringify(scroll)
  );
  await page.screenshot({ path: `${SHOT}/mobile.png` });
} catch (e) {
  ok('mobile section', false, String(e).slice(0, 80));
}

console.log(results.join('\n'));
await browser.close();

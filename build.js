#!/usr/bin/env node
/*
 * Сборка защищённой паролем страницы.
 *
 *   node build.js "пароль"
 *   PROMO_PASSWORD="пароль" node build.js
 *
 * Что происходит:
 *   1. src/ инлайнится в один самодостаточный HTML (CSS, JS и картинка
 *      уезжают внутрь документа — внешних файлов не остаётся).
 *   2. Этот HTML шифруется AES-256-GCM. Ключ выводится из пароля
 *      через PBKDF2-SHA256, 250 000 итераций, случайная соль.
 *   3. index.html собирается из шифротекста и маленькой формы ввода.
 *
 * В репозиторий уезжает только index.html. Без пароля из него
 * ничего не достать: содержимое страницы там лежит шифротекстом.
 * src/ не коммитится (см. .gitignore).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.join(__dirname, 'src');
const OUT = path.join(__dirname, 'index.html');
const ITERATIONS = 250000;

const password = process.argv[2] || process.env.PROMO_PASSWORD;
if (!password) {
  console.error('Не задан пароль.\n  node build.js "пароль"\n  PROMO_PASSWORD="пароль" node build.js');
  process.exit(1);
}

const read = (p) => fs.readFileSync(path.join(SRC, p), 'utf8');

/* ── 1. собрать один самодостаточный документ ─────────────────── */

function inline() {
  let html = read('index.html');

  // Подстановки — только функциями. В строке-замене $$, $&, $` и $' —
  // служебные: строковый вариант превратил бы `const $$ =` из app.js
  // в `const $ =` и уронил бы весь скрипт на разборе.
  const put = (s) => () => s;

  const css = ['tokens.css', 'app.css'].map(read).join('\n\n');
  // оба <link rel=stylesheet> на локальные файлы → один <style>
  html = html.replace(/\n?\s*<link rel="stylesheet" href="tokens\.css">/, '');
  html = html.replace(
    /\s*<link rel="stylesheet" href="app\.css">/,
    put(`\n<style>\n${css}\n</style>`)
  );

  html = html.replace(
    /<script src="app\.js"><\/script>/,
    put(`<script>\n${read('app.js')}\n</script>`)
  );

  // картинка → data: URI
  const png = fs.readFileSync(path.join(SRC, 'assets/promo-illustration.png'));
  html = html.replace(
    'src="assets/promo-illustration.png"',
    put(`src="data:image/png;base64,${png.toString('base64')}"`)
  );

  const leftovers = html.match(/(?:href|src)="(?!https?:|data:|#)[^"]+"/g);
  if (leftovers) throw new Error('Остались внешние ссылки: ' + leftovers.join(', '));

  // сборка молча портила код — держим маркеры под контролем
  for (const [marker, where] of [
    ['const $$ = (sel', 'app.js: хелпер $$ (мог схлопнуться в $)'],
    ['--sheet-ease', 'tokens.css'],
    ['data:image/png;base64,', 'иллюстрация'],
    ['promoShake', 'app.css'],
  ]) {
    if (!html.includes(marker)) throw new Error(`Потерялось при инлайне — ${where}`);
  }

  return html;
}

/* ── 2. зашифровать ──────────────────────────────────────────── */

function encrypt(plaintext) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

  // salt | iv | ciphertext+tag — ровно в таком порядке читает страница
  return Buffer.concat([salt, iv, body, cipher.getAuthTag()]).toString('base64');
}

/* ── 3. страница-замок ───────────────────────────────────────── */

function gate(payload) {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Переходы страницы промокодов</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    display: flex; align-items: center; justify-content: center; padding: 24px;
    font-family: Lato, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: rgb(235,235,235);
    background: radial-gradient(1200px 800px at 30% 20%, #101418 0%, #0a0c0f 60%);
    -webkit-font-smoothing: antialiased;
  }
  form { width: 100%; max-width: 340px; display: flex; flex-direction: column; gap: 14px; }
  .kicker { font-size: 12px; font-weight: 800; letter-spacing: 2.5px; color: rgb(255,192,0); }
  h1 { margin: 0; font-size: 24px; font-weight: 800; line-height: 30px; }
  p  { margin: 0; font-size: 14px; line-height: 20px; color: rgba(235,235,235,.6); }
  input {
    height: 52px; border-radius: 12px; padding: 0 16px; font: inherit; font-size: 16px;
    color: rgb(235,235,235); background: rgba(255,255,255,.07);
    border: 0; box-shadow: inset 0 0 0 1px rgba(255,255,255,.12); outline: none;
  }
  input:focus { box-shadow: inset 0 0 0 2px rgb(255,192,0); }
  button {
    height: 52px; border-radius: 12px; border: 0; font: inherit; font-size: 16px; font-weight: 800;
    background: rgb(255,192,0); color: rgb(15,18,20); cursor: pointer;
  }
  button:hover:not(:disabled) { background: rgb(255,206,51); }
  button:disabled { opacity: .55; cursor: default; }
  .err { font-size: 14px; color: rgb(255,92,92); min-height: 20px; }
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <div class="kicker">ПРОМОКОД · REGULAR</div>
  <h1>Переходы страницы промокодов</h1>
  <p>Страница закрыта паролем. Спроси его у Аси.</p>
  <input id="p" type="password" placeholder="Пароль" autofocus aria-label="Пароль">
  <button id="b" type="submit">Открыть</button>
  <div class="err" id="e" role="alert"></div>
</form>
<script>
(() => {
  'use strict';
  const PAYLOAD = "${payload}";
  const ITERATIONS = ${ITERATIONS};

  const form = document.getElementById('f');
  const input = document.getElementById('p');
  const button = document.getElementById('b');
  const error = document.getElementById('e');

  const bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  async function unlock(password) {
    const raw = bytes(PAYLOAD);
    const salt = raw.slice(0, 16);
    const iv = raw.slice(16, 28);
    const body = raw.slice(28);

    const base = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, body);
    return new TextDecoder().decode(plain);
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!input.value) return;

    button.disabled = true;
    button.textContent = 'Расшифровываю…';
    error.textContent = '';

    try {
      const html = await unlock(input.value);
      document.open();
      document.write(html);
      document.close();
    } catch {
      // GCM не аутентифицировал — пароль неверный
      button.disabled = false;
      button.textContent = 'Открыть';
      error.textContent = 'Неверный пароль';
      input.select();
    }
  });

  if (!crypto.subtle) {
    error.textContent = 'Нужен https:// — без него браузер не даёт расшифровать.';
    button.disabled = true;
  }
})();
</script>
</body>
</html>
`;
}

/* ── поехали ─────────────────────────────────────────────────── */

const plaintext = inline();
const payload = encrypt(plaintext);
fs.writeFileSync(OUT, gate(payload));

const kb = (n) => (n / 1024).toFixed(0) + ' КБ';
console.log(`src/ → ${kb(Buffer.byteLength(plaintext))} инлайн-HTML`);
console.log(`index.html → ${kb(fs.statSync(OUT).size)} (шифротекст + форма ввода)`);

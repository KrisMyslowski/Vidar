/* Measures real layout in a real browser.
 *
 * jsdom parses markup but computes no layout, so a table can be structurally
 * perfect and still render with its columns shifted, collapsed, or half the
 * container wide — which is exactly what shipped twice. This drives
 * chrome-headless-shell over the DevTools protocol (no dependencies: Node's
 * global WebSocket and fetch are enough, from Node 21 on — before that every
 * measurement dies with "WebSocket is not defined") and evaluates a measuring
 * expression inside each page.
 *
 * Usage: node measure.mjs <expression-file> < jobs.json
 *   jobs.json: [{ "key": "...", "url": "...", "width": 1600 }, …]
 *   stdout:    { "<key>": <expression result>, … }
 *
 * One browser for all jobs — starting one per measurement dominated the
 * runtime. Viewport size is set per tab via Emulation, not per process.
 * Exit code 3 means: no browser found — the caller should skip, not fail.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

// A profile of its own, and a port the OS picks. Six fixtures each start their
// own browser, one after another, and a fixed port makes that a race: the next
// process binds while the last one is still letting go, or worse, talks to the
// dying instance because /json/version still answers. Chrome writes the port it
// actually took into DevToolsActivePort, so asking is both correct and cheap.
const PROFILE = mkdtempSync(join(tmpdir(), 'vidar-cdp-'));
const PORT_FILE = join(PROFILE, 'DevToolsActivePort');
let PORT = 0;

function findBrowser() {
  if (process.env.VIDAR_CHROME) return process.env.VIDAR_CHROME;
  const cache = join(homedir(), 'Library/Caches/ms-playwright');
  if (existsSync(cache)) {
    // Playwright names the directory with a build number; take any of them.
    for (const dir of readdirSync(cache)) {
      for (const rel of [
        'chrome-headless-shell-mac-arm64/chrome-headless-shell',
        'chrome-headless-shell-mac-x64/chrome-headless-shell',
        'chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium',
        'chrome-mac/Chromium.app/Contents/MacOS/Chromium',
      ]) {
        const p = join(cache, dir, rel);
        if (existsSync(p)) return p;
      }
    }
  }
  for (const p of [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
  ]) {
    if (existsSync(p)) return p;
  }
  return null;
}

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
  });
}

function cdp(ws) {
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) {
      pending.get(d.id)(d);
      pending.delete(d.id);
    }
  };
  return (method, params, sessionId) =>
    new Promise((resolve, reject) => {
      pending.set(++id, (d) =>
        d.error ? reject(new Error(d.error.message)) : resolve(d.result)
      );
      ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
}

const expression = readFileSync(process.argv[2], 'utf8');
const jobs = JSON.parse(await readStdin());

const browser = findBrowser();
if (!browser) {
  process.stderr.write('no chrome/chromium found (set VIDAR_CHROME)\n');
  process.exit(3);
}

const chrome = spawn(browser, [
  '--headless',
  '--disable-gpu',
  '--hide-scrollbars',
  '--no-sandbox',
  '--remote-debugging-port=0',
  `--user-data-dir=${PROFILE}`,
  'about:blank',
]);
chrome.on('error', (e) => {
  process.stderr.write(String(e) + '\n');
  process.exit(3);
});

// Chrome's own complaint is the only thing that explains a start that never
// happens, and spawn() pipes it into a buffer nobody reads. Keep the tail.
let chromeErr = '';
chrome.stderr.on('data', (b) => {
  chromeErr = (chromeErr + b).slice(-2000);
});

let code = 0;
try {
  // The file appears only once the browser is listening, and its first line is
  // the port. Reading it is what makes this immune to a predecessor still on
  // its way out.
  // Sixty seconds, not ten. The first launch of a run is the slow one — a cold
  // page cache and a 200MB binary — and ten was enough on a warm machine and
  // not on a cold runner, where it failed the seven tests of the first fixture
  // and nothing after it. Waiting longer costs nothing when the browser is
  // quick, which is every time after the first.
  let ready = false;
  for (let i = 0; i < 600 && !ready; i++) {
    try {
      const line = readFileSync(PORT_FILE, 'utf8').split('\n')[0].trim();
      if (line) {
        PORT = Number(line);
        await fetch(`http://127.0.0.1:${PORT}/json/version`);
        ready = true;
      }
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  if (!ready) {
    throw new Error(
      `browser did not start within 60s: ${browser}` +
        (chromeErr ? `\n--- its stderr ---\n${chromeErr}` : ' (it said nothing)')
    );
  }

  const results = {};
  for (const job of jobs) {
    const tab = await (
      await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`, { method: 'PUT' })
    ).json();
    const ws = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = reject;
    });
    const send = cdp(ws);
    await send('Page.enable');
    await send('Runtime.enable');
    await send('Emulation.setDeviceMetricsOverride', {
      width: job.width,
      height: 1200,
      deviceScaleFactor: 1,
      mobile: false,
    });
    const loaded = new Promise((resolve) => {
      ws.addEventListener('message', function onMsg(m) {
        if (JSON.parse(m.data).method === 'Page.loadEventFired') {
          ws.removeEventListener('message', onMsg);
          resolve();
        }
      });
    });
    await send('Page.navigate', { url: job.url });
    await loaded;
    // The page's own scripts (columns.js, theme.js) must have run before we
    // measure — that is the state a reader actually sees.
    await new Promise((r) => setTimeout(r, 350));
    const out = await send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (out.exceptionDetails) {
      throw new Error(
        `${job.key}: ${out.exceptionDetails.exception?.description || 'evaluation failed'}`
      );
    }
    results[job.key] = out.result.value;
    ws.close();
    await fetch(`http://127.0.0.1:${PORT}/json/close/${tab.id}`);
  }
  // process.exit() truncates a pending pipe write, and the report is well past
  // the 64KB buffer — wait for the flush before leaving.
  await new Promise((done) => process.stdout.write(JSON.stringify(results), done));
} catch (e) {
  process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
  code = 1;
} finally {
  // kill() is a signal, not a stop: Chrome keeps writing into its profile for a
  // moment afterwards, so removing the directory raced it and lost with
  // ENOTEMPTY — after the report had already been written, which turned a good
  // measurement into a failed one. Wait for the exit, and never let tidying up
  // be the reason a run fails. A leftover directory under /tmp is nothing.
  chrome.kill();
  await new Promise((done) => {
    const timer = setTimeout(done, 5000);
    chrome.once('exit', () => {
      clearTimeout(timer);
      done();
    });
  });
  try {
    rmSync(PROFILE, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    /* not ours to care about */
  }
}
process.exit(code);

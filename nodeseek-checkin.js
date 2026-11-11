/**
 * Loon — NodeSeek 自动签到
 * 接口：POST https://www.nodeseek.com/api/attendance?random=true
 * 依赖：登录后的 Cookie（含 session） + 对应 UA
 *
 * Loon 配置：
 *
 * [Script]
 * # 1) 抓 Cookie：登录 nodeseek.com 后刷新任意页面
 * http-request ^https?:\/\/www\.nodeseek\.com\/ script-path=https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js, requires-body=false, timeout=10, tag=NodeSeek抓Cookie, argument=action=capture
 * # 2) 每天 00:10 签到
 * cron "10 0 * * *" script-path=https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js, timeout=60, tag=NodeSeek签到, argument=action=checkin
 *
 * [MITM]
 * hostname = %APPEND% www.nodeseek.com
 *
 * 多账号：退出登录换号，再刷新页面抓一次即可，脚本按 Cookie 去重保存。
 */

const CONFIG = {
  cookieKey: 'nodeseek_cookie', // 存放 Cookie 的 persistentStore key
  random: true,                 // true=一试手气；false=固定鸡腿（接口的 random 参数）
  loginCookieName: 'session',   // 登录态 Cookie 名，没有它就不保存
  notifyAlways: true,           // false=只在失败时通知
  retry: 1,
  timeout: 15000,
  interval: 800,                // 多账号间隔(ms)
  debug: false,                 // true=把响应体写进 Loon 日志
};

const API = () => `https://www.nodeseek.com/api/attendance?random=${CONFIG.random}`;

const store = {
  read(key) { return $persistentStore.read(key) || ''; },
  write(value, key) { return $persistentStore.write(value, key); },
};

function getHeader(headers, name) {
  if (!headers) return '';
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : '';
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function parseArgs(raw) {
  const out = {};
  if (!raw) return out;
  String(raw).split('&').forEach((pair) => {
    const i = pair.indexOf('=');
    if (i > 0) out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  });
  return out;
}

/* ---------------- 多账号存取 ---------------- */
function loadAccounts() {
  const raw = store.read(CONFIG.cookieKey);
  if (!raw) return [];
  return raw.split('\n').filter(Boolean).map((line) => {
    const i = line.indexOf('|||');
    return i === -1
      ? { cookie: line, ua: '' }
      : { cookie: line.slice(0, i), ua: line.slice(i + 3) };
  }).filter((a) => a.cookie);
}

function saveAccount(cookie, ua) {
  const list = loadAccounts();
  if (list.some((a) => a.cookie === cookie)) return false;
  list.push({ cookie, ua: ua || '' });
  store.write(list.map((a) => a.cookie + '|||' + a.ua).join('\n'), CONFIG.cookieKey);
  return true;
}

/* ---------------- HTTP ---------------- */
function httpOnce(opts) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => finish({ err: 'TIMEOUT' }), CONFIG.timeout + 3000);
    function finish(v) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(v);
    }
    try {
      const fn = String(opts.method || 'GET').toUpperCase() === 'POST' ? $httpClient.post : $httpClient.get;
      fn(opts, (err, resp, data) => finish({ err, resp, data }));
    } catch (e) {
      finish({ err: e });
    }
  });
}

async function http(opts) {
  let last = null;
  for (let i = 0; i <= CONFIG.retry; i++) {
    last = await httpOnce(opts);
    if (!last.err) return last;
    if (i < CONFIG.retry) await sleep(1000);
  }
  return last;
}

/* ---------------- 签到结果判定 ---------------- */
function judge(raw) {
  const text = String(raw || '').trim();
  let d = null;
  try { d = JSON.parse(text); } catch (e) {}

  const msg = (d && (d.message || d.msg)) || text || '空响应';

  if (d && d.success === true) return { ok: true, msg };
  if (/鸡腿/.test(msg)) return { ok: true, msg };
  if (/已完成签到|已签到|已经签到/.test(msg)) return { ok: true, msg };
  if (/未登录|请先登录|登录已过期|登录失效/.test(msg)) return { ok: false, msg };
  if (d && d.status === 404) return { ok: false, msg: msg || '未登录或账号异常' };
  return { ok: false, msg: String(msg).slice(0, 120) };
}

/* ---------------- 模式一：抓 Cookie ---------------- */
function capture() {
  const req = $request || {};
  const headers = req.headers || {};
  const cookie = getHeader(headers, 'Cookie');
  const ua = getHeader(headers, 'User-Agent');

  if (!cookie) {
    console.log('NodeSeek capture: 请求无 Cookie -> ' + req.url);
    $done({});
    return;
  }

  if (CONFIG.loginCookieName && !new RegExp(CONFIG.loginCookieName + '=').test(cookie)) {
    console.log('NodeSeek capture: 未检测到登录 Cookie，忽略');
    $done({});
    return;
  }

  const added = saveAccount(cookie, ua);
  const total = loadAccounts().length;
  console.log(`NodeSeek capture: ${added ? 'saved' : 'exists'}, total=${total}`);

  if (added) {
    $notification.post('NodeSeek Cookie 已保存', '', `当前账号数：${total}`);
  }
  $done({});
}

/* ---------------- 模式二：签到 ---------------- */
async function checkin() {
  const accounts = loadAccounts();
  if (!accounts.length) {
    $notification.post('NodeSeek 签到', '', '未抓到 Cookie，请先在 Loon 里打开 NodeSeek 并刷新页面');
    $done({});
    return;
  }

  const lines = [];
  let success = 0;
  let failed = 0;

  for (let i = 0; i < accounts.length; i++) {
    const acc = accounts[i];
    const label = accounts.length > 1 ? `账号#${i + 1}` : 'NodeSeek';

    const headers = {
      Accept: 'application/json, text/plain, */*',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'Content-Type': 'application/json',
      Origin: 'https://www.nodeseek.com',
      Referer: 'https://www.nodeseek.com/board',
      Cookie: acc.cookie,
    };
    if (acc.ua) headers['User-Agent'] = acc.ua;

    const { err, resp, data } = await http({
      url: API(),
      method: 'POST',
      headers,
    });

    if (err) {
      lines.push(`${label}: [FAIL] ${err}`);
      failed++;
      continue;
    }

    const status = (resp && (resp.status || resp.statusCode)) || 0;
    if (status >= 400) {
      const hint = status === 403 ? '（可能被 Cloudflare 拦截，换网络或重新抓 Cookie）' : '';
      lines.push(`${label}: [FAIL] HTTP ${status}${hint}`);
      if (CONFIG.debug) console.log(`[${label}] ${data}`);
      failed++;
      continue;
    }

    const result = judge(data);
    if (CONFIG.debug) console.log(`[${label}] ${data}`);
    result.ok ? success++ : failed++;
    lines.push(`${label}: ${result.ok ? '[OK]' : '[FAIL]'} ${result.msg}`);

    await sleep(CONFIG.interval);
  }

  const body = lines.join('\n');
  console.log(body);
  if (CONFIG.notifyAlways || failed > 0) {
    $notification.post(
      failed ? `NodeSeek 签到完成（失败 ${failed}）` : `NodeSeek 签到完成（成功 ${success}）`,
      '',
      body
    );
  }
  $done({});
}

/* ---------------- 入口 ---------------- */
(async () => {
  const args = parseArgs($argument);
  const action = args.action || 'checkin';
  if (action === 'capture') return capture();
  return checkin();
})().catch((e) => {
  const msg = (e && e.stack) || String(e);
  console.log('NodeSeek script error: ' + msg);
  $notification.post('NodeSeek 签到异常', '', (e && e.message) || String(e));
  $done({});
});

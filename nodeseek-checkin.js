/**
 * Loon — NodeSeek 自动签到
 * 接口：POST https://www.nodeseek.com/api/attendance?random=true
 * 依赖：登录后的 Cookie（含 session） + 对应 UA
 *
 * Loon 3.5.1 (983) 起的新版 Script 语法（推荐）：
 *
 * [Script]
 * # 1) 抓 Cookie：登录 nodeseek.com 后刷新任意页面（只能在请求里触发，不能手动运行）
 * request if ${url} ~= /^https?:\/\/www\.nodeseek\.com\// then script("https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js", "action=capture") with tag="NodeSeek抓Cookie", timeout=20, requires_body=false
 * # 2) 每天 00:10 签到
 * cron "10 0 * * *" then script("https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js", "action=checkin") with tag="NodeSeek签到", timeout=300
 * # 3) 可选：给一个可手动运行的入口
 * generic then script("https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js", "action=checkin") with tag="NodeSeek手动签到", timeout=300
 *
 * 旧版语法（Loon 仍兼容）：
 * http-request ^https?:\/\/www\.nodeseek\.com\/ script-path=https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js, requires-body=false, timeout=10, tag=NodeSeek抓Cookie, argument=action=capture
 * cron "10 0 * * *" script-path=https://raw.githubusercontent.com/you/repo/main/nodeseek-checkin.js, timeout=60, tag=NodeSeek签到, argument=action=checkin
 *
 * [MITM]
 * hostname = %APPEND% www.nodeseek.com, nodeseek.com
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
  read(key) {
    try {
      return (typeof $persistentStore !== 'undefined' && $persistentStore.read(key)) || '';
    } catch (e) {
      console.log('persistentStore.read error: ' + e);
      return '';
    }
  },
  write(value, key) {
    try {
      if (typeof $persistentStore === 'undefined') throw new Error('$persistentStore 不可用');
      $persistentStore.write(value, key);
      return true;
    } catch (e) {
      console.log('persistentStore.write error: ' + e);
      return false;
    }
  },
};

function notify(title, subtitle, body) {
  try {
    if (typeof $notification !== 'undefined' && $notification.post) {
      $notification.post(title || '', subtitle || '', body || '');
    }
  } catch (e) {
    console.log('notification error: ' + e);
  }
}

function safeDone(result) {
  try {
    if (typeof $done === 'undefined') return;
    // Request Script 必须传 {} 才放行；Cron/Generic 用无参 $done() 结束
    if (result === undefined || result === null) $done();
    else $done(result);
  } catch (e) {
    console.log('$done error: ' + e);
  }
}

function readArgument() {
  try {
    return typeof $argument !== 'undefined' ? $argument : '';
  } catch (e) {
    return '';
  }
}

function currentRequest() {
  try {
    return typeof $request !== 'undefined' && $request ? $request : null;
  } catch (e) {
    return null;
  }
}

function getHeader(headers, name) {
  if (!headers) return '';
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : '';
}

function toText(data) {
  if (data === undefined || data === null) return '';
  if (typeof data === 'string') return data;
  try {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(data);
  } catch (e) {}
  try {
    return String.fromCharCode.apply(null, data);
  } catch (e) {
    return String(data);
  }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function parseArgs(raw) {
  const out = {};
  if (!raw) return out;
  if (typeof raw === 'object') {
    Object.keys(raw).forEach((k) => { out[k] = String(raw[k]); });
    return out;
  }
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
  if (list.some((a) => a.cookie === cookie)) return 'exists';
  list.push({ cookie, ua: ua || '' });
  return store.write(list.map((a) => a.cookie + '|||' + a.ua).join('\n'), CONFIG.cookieKey)
    ? 'saved'
    : 'error';
}

/* ---------------- HTTP ---------------- */
function httpOnce(opts) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => finish({ err: 'TIMEOUT' }), CONFIG.timeout + 3000);
    function finish(v) {
      if (settled) return;
      settled = true;
      try {
        // 官方文档说明 clearTimeout 在部分运行时不可靠，存在才调用
        if (typeof clearTimeout === 'function') clearTimeout(timer);
      } catch (e) {}
      resolve(v);
    }
    try {
      const params = Object.assign({ timeout: CONFIG.timeout }, opts);
      const fn = String(params.method || 'GET').toUpperCase() === 'POST' ? $httpClient.post : $httpClient.get;
      fn(params, (err, resp, data) => finish({ err, resp, data }));
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
  const req = currentRequest();
  if (!req) {
    const msg = '没有 $request：抓 Cookie 必须由 request/http-request 类型的规则触发，手动运行脚本是抓不到的。\n请登录 NodeSeek 后刷新页面（并确认规则类型是 Request Script）。';
    console.log('NodeSeek capture: $request 不存在');
    notify('NodeSeek 抓 Cookie 失败', '', msg);
    safeDone();
    return;
  }

  const headers = req.headers || {};
  const cookie = getHeader(headers, 'Cookie');
  const ua = getHeader(headers, 'User-Agent');
  console.log('NodeSeek capture: url=' + req.url + ', cookie=' + (cookie ? 'yes' : 'no'));

  if (!cookie) {
    console.log('NodeSeek capture: 请求无 Cookie -> ' + req.url);
    safeDone({});
    return;
  }

  if (CONFIG.loginCookieName && !new RegExp(CONFIG.loginCookieName + '=').test(cookie)) {
    console.log('NodeSeek capture: 未检测到登录 Cookie，忽略');
    safeDone({});
    return;
  }

  const before = loadAccounts().length;
  const status = saveAccount(cookie, ua);
  const total = status === 'saved' ? before + 1 : before;
  console.log(`NodeSeek capture: ${status}, total=${total}`);

  if (status === 'saved') {
    notify('NodeSeek Cookie 已保存', '', `当前账号数：${total}`);
  } else if (status === 'error') {
    notify('NodeSeek Cookie 保存失败', '', '$persistentStore 写入失败，请检查 Loon 版本或存储权限');
  }
  safeDone({});
}

/* ---------------- 模式二：签到 ---------------- */
async function checkin() {
  const accounts = loadAccounts();
  if (!accounts.length) {
    notify('NodeSeek 签到', '', '未抓到 Cookie，请先在 Loon 里打开 NodeSeek 并刷新页面');
    safeDone();
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
      if (CONFIG.debug) console.log(`[${label}] ${toText(data)}`);
      failed++;
      continue;
    }

    const result = judge(toText(data));
    if (CONFIG.debug) console.log(`[${label}] ${toText(data)}`);
    result.ok ? success++ : failed++;
    lines.push(`${label}: ${result.ok ? '[OK]' : '[FAIL]'} ${result.msg}`);

    await sleep(CONFIG.interval);
  }

  const body = lines.join('\n');
  console.log(body);
  if (CONFIG.notifyAlways || failed > 0) {
    notify(
      failed ? `NodeSeek 签到完成（失败 ${failed}）` : `NodeSeek 签到完成（成功 ${success}）`,
      '',
      body
    );
  }
  safeDone();
}

/* ---------------- 入口 ---------------- */
(async () => {
  const args = parseArgs(readArgument());
  const action = args.action || 'checkin';
  if (action === 'capture') return capture();
  return checkin();
})().catch((e) => {
  const message = (e && e.message) ? e.message : String(e);
  const stack = (e && e.stack) || '';
  console.log('NodeSeek script error: ' + message + (stack ? '\n' + stack : ''));
  notify('NodeSeek 脚本异常', '', message);
  // 请求脚本必须传 {} 放行；Cron/Generic 用无参结束
  safeDone(currentRequest() ? {} : undefined);
});

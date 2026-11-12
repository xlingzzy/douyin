/**
 * Loon — NodeSeek 签到
 * 移植自 QX 脚本：https://raw.githubusercontent.com/ZenmoFeiShi/Qx/refs/heads/main/Nodeseek_NsCheckin.js
 *
 * 思路：
 *   1. 打开 NodeSeek 个人资料页时，抓取该请求的 Cookie / UA / refract-* 等请求头并保存（只存一份）
 *   2. 定时用保存的请求头重放 POST https://www.nodeseek.com/api/attendance?random=true
 *
 * Loon 3.5.1 (983)+ 新语法：
 * [Script]
 * request if ${url} ~= /\/api\/account\/getInfo\/\d+\?readme=1/ then script("https://你的地址/nodeseek-loon.js", "action=capture") with tag="NS抓Header", timeout=20
 * cron "1 0 * * *" then script("https://你的地址/nodeseek-loon.js", "action=checkin") with tag="NS签到", timeout=300
 *
 * 旧语法（Loon 仍兼容）：
 * http-request ^https:\/\/www\.nodeseek\.com\/api\/account\/getInfo\/\d+\?readme=1 script-path=https://你的地址/nodeseek-loon.js, requires-body=false, timeout=10, tag=NS抓Header, argument=action=capture
 * cron "1 0 * * *" script-path=https://你的地址/nodeseek-loon.js, timeout=60, tag=NS签到, argument=action=checkin
 *
 * [MITM]
 * hostname = %APPEND% www.nodeseek.com
 *
 * 使用：开启 Loon 代理和 MITM → Safari 登录 NodeSeek → 点自己头像进入资料页
 *       看到「NS 请求头已保存」即可，之后每天 00:01 自动签到。
 *
 * 说明：保存的是“一份”请求头，不会再出现一个账号被拆成多个的问题。
 *       若签到遇到 403 风控，重新打开一次个人资料页刷新请求头即可。
 */

const CONFIG = {
  headerKey: 'NS_NodeseekHeaders',
  random: true,
  notifyAlways: true,
  timeout: 15000,
  retry: 1,
  debug: false,
};

/* 原 QX 脚本需要的请求头 */
const NEED_KEYS = [
  'Connection',
  'Accept-Encoding',
  'Priority',
  'Content-Type',
  'Origin',
  'refract-sign',
  'User-Agent',
  'refract-key',
  'Sec-Fetch-Mode',
  'Cookie',
  'Host',
  'Referer',
  'Accept-Language',
  'Accept',
];

/* 重放时交给 Loon 自己管理的传输层头 */
const DROP_KEYS = ['host', 'connection', 'accept-encoding', 'content-length'];

/* ---------------- 基础工具 ---------------- */
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
      return $persistentStore.write(value, key) === true;
    } catch (e) {
      console.log('persistentStore.write error: ' + e);
      return false;
    }
  },
};

/* ---------------- 抓取请求头 ---------------- */
function pickNeedHeaders(src) {
  const dst = {};
  NEED_KEYS.forEach((name) => {
    const v = getHeader(src || {}, name);
    if (v !== '' && v !== undefined && v !== null) dst[name] = v;
  });
  return dst;
}

function capture() {
  const req = currentRequest();
  if (!req) {
    notify(
      'NS 抓取失败',
      '',
      '没有 $request：该脚本只能在 Request Script 中抓取，不能手动运行。请登录 NodeSeek 后点自己的头像进入资料页。'
    );
    safeDone();
    return;
  }

  const picked = pickNeedHeaders(req.headers || {});
  const cookie = picked.Cookie || '';

  if (!cookie || !/session=/.test(cookie)) {
    console.log('NS capture: 未找到登录 Cookie -> ' + req.url);
    notify('NS 抓取失败', '', '请求里没有登录 Cookie（session），请确认已登录后再进入个人资料页。');
    safeDone({});
    return;
  }

  if (!picked['refract-key'] && !picked['refract-sign']) {
    console.log('NS capture: 警告，未捕获 refract-key / refract-sign');
  }

  const ok = store.write(JSON.stringify(picked), CONFIG.headerKey);
  console.log(`NS capture: ${ok ? 'saved' : 'failed'}, keys=${Object.keys(picked).join(',')}`);

  if (ok) {
    notify(
      'NS 请求头已保存',
      '',
      `Cookie 长度 ${cookie.length}，refract ${picked['refract-key'] ? '已捕获' : '未捕获'}`
    );
  } else {
    notify('NS 请求头保存失败', '', '$persistentStore 写入失败，请检查 Loon 版本');
  }
  safeDone({});
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

function buildHeaders(saved) {
  const headers = {};
  Object.keys(saved || {}).forEach((k) => {
    if (DROP_KEYS.includes(k.toLowerCase())) return;
    if (saved[k] !== undefined && saved[k] !== null) headers[k] = String(saved[k]);
  });

  if (!getHeader(headers, 'Content-Type')) headers['Content-Type'] = 'text/plain;charset=UTF-8';
  if (!getHeader(headers, 'Origin')) headers.Origin = 'https://www.nodeseek.com';
  if (!getHeader(headers, 'Referer')) headers.Referer = 'https://www.nodeseek.com/board';
  if (!getHeader(headers, 'Accept')) headers.Accept = '*/*';
  return headers;
}

/* ---------------- 签到 ---------------- */
async function checkin() {
  const raw = store.read(CONFIG.headerKey);
  if (!raw) {
    notify('NS签到结果', '无法签到', '本地没有已保存的请求头，请先登录 NodeSeek 并点自己的头像进入资料页。');
    safeDone();
    return;
  }

  let saved = null;
  try {
    saved = JSON.parse(raw);
  } catch (e) {
    notify('NS签到结果', '无法签到', '保存的请求头已损坏，请重新进入一次个人资料页。');
    safeDone();
    return;
  }

  const headers = buildHeaders(saved);
  if (!getHeader(headers, 'Cookie')) {
    notify('NS签到结果', '无法签到', '保存的请求头里没有 Cookie，请重新抓取。');
    safeDone();
    return;
  }

  const url = `https://www.nodeseek.com/api/attendance?random=${CONFIG.random}`;
  const { err, resp, data } = await http({
    url,
    method: 'POST',
    headers,
    body: '',
  });

  if (err) {
    console.log('NS签到请求失败: ' + err);
    notify('NS签到结果', '请求错误', String(err));
    safeDone();
    return;
  }

  const status = (resp && (resp.status || resp.statusCode)) || 0;
  const text = toText(data);
  if (CONFIG.debug) console.log(`NS签到响应 [${status}]: ${text}`);

  let parsed = null;
  try { parsed = JSON.parse(text); } catch (e) {}
  const msg = (parsed && (parsed.message || parsed.msg)) || '';

  if (status === 403) {
    notify('NS签到结果', '403 风控', (msg || text || '被风控拦截') + '\n重新打开一次个人资料页刷新请求头后再试。');
  } else if (status === 500) {
    notify('NS签到结果', '500 服务器错误', msg || text || '服务器错误，无返回内容');
  } else if (status >= 200 && status < 300) {
    const expired = parsed && parsed.success === false && /未登录|登录已过期|登录失效/.test(msg);
    if (expired) {
      notify('NS签到结果', '登录已失效', msg + '\n请重新登录后进入个人资料页抓取请求头。');
    } else {
      notify('NS签到结果', '签到成功', msg || '签到成功，但未返回 message');
    }
  } else {
    notify('NS签到结果', `请求异常 ${status}`, msg || text || `请求失败，status=${status}`);
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
  console.log('NS script error: ' + message + (stack ? '\n' + stack : ''));
  notify('NS 脚本异常', '', message);
  safeDone(currentRequest() ? {} : undefined);
});

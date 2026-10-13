// SwitchBot ロックプロを解錠する Scriptable 用スクリプト
//
// ・Scriptable アプリで開いたとき: 初回設定 / 解錠テスト / 設定のやり直し
// ・ショートカットから実行したとき: 確認なしで解錠（確認はオートメーション側の「確認後に実行」で行う）
//
// トークンとシークレットは iPhone のキーチェーンに保存し、このファイルには書かない。
// 通信先は SwitchBot 公式 API（https://api.switch-bot.com/v1.1）だけ。

const API = "https://api.switch-bot.com/v1.1";
const KEY = {
  token: "switchbot_token",
  secret: "switchbot_secret",
  device: "switchbot_lock_device_id",
  name: "switchbot_lock_name",
};

// ---- SHA-256 / HMAC-SHA256 / Base64（Scriptable には暗号ライブラリがないため自前で計算する） ----

function utf8Bytes(str) {
  const s = unescape(encodeURIComponent(str));
  const out = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
  return out;
}

const SHA256_H = [];
const SHA256_K = [];
(function initConstants() {
  const primes = [];
  for (let n = 2; primes.length < 64; n++) {
    if (primes.every((p) => n % p !== 0)) primes.push(n);
  }
  primes.forEach((p, i) => {
    if (i < 8) SHA256_H.push((Math.pow(p, 1 / 2) * 0x100000000) | 0);
    SHA256_K.push((Math.pow(p, 1 / 3) * 0x100000000) | 0);
  });
})();

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function sha256(bytes) {
  const msg = bytes.slice();
  const bitLen = bytes.length * 8;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  for (const word of [hi, lo]) {
    msg.push((word >>> 24) & 255, (word >>> 16) & 255, (word >>> 8) & 255, word & 255);
  }

  const h = SHA256_H.slice();
  const w = new Array(64);
  for (let i = 0; i < msg.length; i += 64) {
    for (let j = 0; j < 16; j++) {
      const o = i + j * 4;
      w[j] = (msg[o] << 24) | (msg[o + 1] << 16) | (msg[o + 2] << 8) | msg[o + 3];
    }
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
      const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let j = 0; j < 64; j++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[j] + w[j]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    [a, b, c, d, e, f, g, hh].forEach((v, k) => (h[k] = (h[k] + v) | 0));
  }

  const out = [];
  for (const v of h) out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  return out;
}

function hmacSha256(key, msg) {
  let k = key.length > 64 ? sha256(key) : key.slice();
  while (k.length < 64) k.push(0);
  const inner = sha256(k.map((b) => b ^ 0x36).concat(msg));
  return sha256(k.map((b) => b ^ 0x5c).concat(inner));
}

function base64(bytes) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += chars[(n >>> 18) & 63] + chars[(n >>> 12) & 63];
    out += i + 1 < bytes.length ? chars[(n >>> 6) & 63] : "=";
    out += i + 2 < bytes.length ? chars[n & 63] : "=";
  }
  return out;
}

function uuid() {
  const hex = "0123456789abcdef";
  let s = "";
  for (let i = 0; i < 32; i++) {
    s += hex[Math.floor(Math.random() * 16)];
    if (i === 7 || i === 11 || i === 15 || i === 19) s += "-";
  }
  return s;
}

function signHeaders(token, secret) {
  const t = String(Date.now());
  const nonce = uuid();
  const sign = base64(hmacSha256(utf8Bytes(secret), utf8Bytes(token + t + nonce)));
  return {
    Authorization: token,
    sign: sign,
    t: t,
    nonce: nonce,
    "Content-Type": "application/json; charset=utf8",
  };
}

// ---- SwitchBot API ----

async function callApi(method, path, body) {
  const req = new Request(API + path);
  req.method = method;
  req.headers = signHeaders(Keychain.get(KEY.token), Keychain.get(KEY.secret));
  if (body) req.body = JSON.stringify(body);
  req.timeoutInterval = 15;
  const res = await req.loadJSON();
  if (res.statusCode !== 100) {
    const code = res.statusCode ?? req.response?.statusCode;
    throw new Error(`SwitchBot API エラー（${code}）: ${res.message}`);
  }
  return res.body;
}

async function unlock() {
  const id = Keychain.get(KEY.device);
  await callApi("POST", `/devices/${id}/commands`, {
    command: "unlock",
    parameter: "default",
    commandType: "command",
  });
}

function isConfigured() {
  return [KEY.token, KEY.secret, KEY.device].every((k) => Keychain.contains(k));
}

function clearSettings() {
  Object.values(KEY).forEach((k) => {
    if (Keychain.contains(k)) Keychain.remove(k);
  });
}

// ---- 画面（Scriptable アプリで開いたときだけ使う） ----

async function showMessage(title, message) {
  const a = new Alert();
  a.title = title;
  a.message = message;
  a.addAction("OK");
  await a.presentAlert();
}

async function choose(title, message, options) {
  const a = new Alert();
  a.title = title;
  a.message = message;
  options.forEach((o) => a.addAction(o));
  a.addCancelAction("キャンセル");
  return await a.presentAlert(); // キャンセルは -1
}

async function setup() {
  const a = new Alert();
  a.title = "SwitchBot の初期設定";
  a.message =
    "SwitchBot アプリの「開発者向けオプション」に表示される\nトークンとクライアントシークレットを貼り付けてください。";
  a.addTextField("トークン", "");
  a.addSecureTextField("クライアントシークレット", "");
  a.addAction("次へ");
  a.addCancelAction("キャンセル");
  if ((await a.presentAlert()) === -1) return false;

  const token = a.textFieldValue(0).trim();
  const secret = a.textFieldValue(1).trim();
  if (!token || !secret) {
    await showMessage("入力が足りません", "トークンとクライアントシークレットの両方を入力してください。");
    return false;
  }
  Keychain.set(KEY.token, token);
  Keychain.set(KEY.secret, secret);

  let devices;
  try {
    devices = await callApi("GET", "/devices");
  } catch (e) {
    clearSettings();
    await showMessage("接続できませんでした", `${e.message}\n\nトークンとシークレットを確認してください。`);
    return false;
  }

  const locks = (devices.deviceList || []).filter((d) => /lock/i.test(d.deviceType || ""));
  if (locks.length === 0) {
    clearSettings();
    await showMessage(
      "ロックが見つかりません",
      "SwitchBot アカウントにロックが登録されているか確認してください。"
    );
    return false;
  }

  let lock = locks[0];
  if (locks.length > 1) {
    const i = await choose(
      "どのロックを使いますか？",
      "",
      locks.map((d) => `${d.deviceName}（${d.deviceType}）`)
    );
    if (i === -1) {
      clearSettings();
      return false;
    }
    lock = locks[i];
  }

  Keychain.set(KEY.device, lock.deviceId);
  Keychain.set(KEY.name, lock.deviceName);

  let note = "";
  if (lock.enableCloudService === false) {
    note =
      "\n\n⚠ このロックは「クラウドサービス」がオフです。SwitchBot アプリでロックの設定を開き、クラウドサービスをオンにしてください。オフのままだと解錠できません。";
  }
  await showMessage("設定しました", `使うロック: ${lock.deviceName}${note}`);
  return true;
}

async function runInApp() {
  if (!isConfigured()) {
    if (!(await setup())) return;
  }
  const name = Keychain.contains(KEY.name) ? Keychain.get(KEY.name) : "ロック";
  const i = await choose(name, "操作を選んでください。", ["🔓 今すぐ解錠する", "設定をやり直す"]);
  if (i === 0) {
    try {
      await unlock();
      await showMessage("解錠しました", `${name} に解錠の命令を送りました。`);
    } catch (e) {
      await showMessage("解錠できませんでした", e.message);
    }
  } else if (i === 1) {
    clearSettings();
    await setup();
  }
}

async function runFromShortcut() {
  if (!isConfigured()) {
    const msg = "未設定です。先に Scriptable アプリでこのスクリプトを開いて設定してください。";
    Script.setShortcutOutput(msg);
    throw new Error(msg);
  }
  await unlock();
  Script.setShortcutOutput("解錠しました");
}

// ---- main ----

if (config.runsInApp) {
  await runInApp();
} else {
  await runFromShortcut();
}
Script.complete();

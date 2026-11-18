'use strict';
const form = document.getElementById('login');
const entrance = document.getElementById('entrance');
const password = document.getElementById('password');
const enter = document.getElementById('enter');
const statusLine = document.getElementById('status');
const lock = document.getElementById('lock');
const root = new URL('./', location.href);
const encoder = new TextEncoder();
let active = null;
let frame = null;

function openEnvelope(key, bytes, label) {
  return crypto.subtle.decrypt({
    name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: encoder.encode(label)
  }, key, bytes.subarray(12));
}

async function getSession(secret) {
  const header = await fetch(new URL('release.json', root), {cache: 'no-store', referrerPolicy: 'no-referrer'});
  if (!header.ok) throw Error('배포 정보를 읽을 수 없어요. 잠시 후 다시 열어 주세요.');
  const params = await header.json();
  const response = await fetch(new URL(params.manifest, root));
  if (!response.ok) throw Error('암호화한 파일 목록을 내려받지 못했어요.');
  const envelope = new Uint8Array(await response.arrayBuffer());
  const seed = await crypto.subtle.importKey('raw', encoder.encode(secret), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({
    name: 'PBKDF2', hash: 'SHA-256', iterations: params.rounds,
    salt: Uint8Array.from(atob(params.salt), c => c.charCodeAt(0))
  }, seed, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
  let manifest;
  try {
    manifest = await openEnvelope(key, envelope, 'orbit-manifest-v1');
  } catch {
    throw Error('암호가 맞지 않아요. 다시 입력해 주세요.');
  }
  const {files, packs} = JSON.parse(new TextDecoder().decode(manifest));
  return {key, files, packs, whole: new Map(), pending: new Map(), cancel: new AbortController(),
          token: crypto.randomUUID().replace(/-/g, '')};
}

async function readFile(session, path) {
  if (!Object.hasOwn(session.files, path)) return {status: 404};
  const [index, start, length, mime] = session.files[path];
  const blob = session.packs[index];
  let encrypted;
  if (session.whole.has(blob)) {
    encrypted = session.whole.get(blob).subarray(start, start + length);
  } else {
    const end = start + length - 1;
    const response = await fetch(new URL(blob, root), {
      headers: {Range: 'bytes=' + start + '-' + end}, signal: session.cancel.signal,
      referrerPolicy: 'no-referrer'
    });
    if (!response.ok) throw Error('관측 자료를 불러올 수 없어요.');
    const data = new Uint8Array(await response.arrayBuffer());
    if (response.status === 206) {
      encrypted = data;
    } else {
      // Some static servers return the entire encrypted pack to a range request.
      if (!session.whole.has(blob) && session.whole.size >= 3) session.whole.delete(session.whole.keys().next().value);
      session.whole.set(blob, data);
      encrypted = data.subarray(start, start + length);
    }
  }
  if (encrypted.length !== length) throw Error('관측 자료가 온전히 도착하지 않았어요.');
  const bytes = await openEnvelope(session.key, encrypted, 'orbit-resource-v1/' + path);
  return {status: 200, mime, bytes};
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', async event => {
    const message = event.data;
    const port = event.ports[0];
    if (!port || !message || event.source?.scriptURL !== new URL('sw.js', root).href) return;
    const session = active;
    const matches = !!session && message.token === session.token;
    if (message.type === 'probe') { port.postMessage(matches); return; }
    if (!matches || message.type !== 'read') {port.postMessage({status: 401}); return;}
    try {
      // Each message transfers its own buffer. Never transfer or persist the key.
      const pending = session.pending.get(message.path) || readFile(session, message.path);
      session.pending.set(message.path, pending);
      let resource;
      try { resource = await pending; } finally {session.pending.delete(message.path);}
      if (session !== active) {port.postMessage({status: 401}); return;}
      if (!resource.bytes) {port.postMessage(resource); return;}
      const bytes = resource.bytes.slice(0);
      port.postMessage({status: 200, mime: resource.mime, bytes}, [bytes]);
    } catch {
      port.postMessage({status: 503});
    }
  });
}

async function controller() {
  await navigator.serviceWorker.register(new URL('sw.js', root), {updateViaCache: 'none'});
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve, reject) => {
      function changed() {
        if (!navigator.serviceWorker.controller) return;
        clearTimeout(timer);
        navigator.serviceWorker.removeEventListener('controllerchange', changed);
        resolve();
      }
      const timer = setTimeout(() => {
        navigator.serviceWorker.removeEventListener('controllerchange', changed);
        reject(Error('보호된 화면을 준비하지 못했어요. 새로고침 후 다시 열어 주세요.'));
      }, 12000);
      navigator.serviceWorker.addEventListener('controllerchange', changed);
      changed();
    });
  }
  return navigator.serviceWorker.controller;
}

function resetSession() {
  if (active) {
    navigator.serviceWorker.controller?.postMessage({type: 'close', token: active.token});
    active.cancel.abort();
    active.whole.clear();
    active.pending.clear();
    active = null;
  }
  if (frame) {frame.remove(); frame = null;}
  lock.hidden = true;
  entrance.hidden = false;
  password.value = '';
  enter.disabled = false;
  statusLine.textContent = '';
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (enter.disabled) return;
  enter.disabled = true;
  statusLine.textContent = '암호를 확인하고 있어요…';
  try {
    if (!crypto.subtle || !('serviceWorker' in navigator))
      throw Error('HTTPS 주소를 사파리, 크롬 또는 엣지에서 열어 주세요.');
    const session = await getSession(password.value);
    const worker = await controller();
    active = session;
    password.value = '';
    worker.postMessage({type: 'open', token: session.token});
    const url = new URL('v/' + session.token + '/', root);
    const query = new URLSearchParams(location.search);
    if (query.get('view') === 'observatory') url.pathname += 'observatory/';
    query.delete('view');
    url.search = query;
    url.hash = location.hash;
    frame = document.createElement('iframe');
    frame.id = 'scene';
    frame.title = '태양계 실험실';
    frame.allow = 'fullscreen';
    frame.allowFullscreen = true;
    frame.referrerPolicy = 'no-referrer';
    frame.src = url.href;
    document.body.append(frame);
    entrance.hidden = true;
    lock.hidden = false;
  } catch (err) {
    resetSession();
    statusLine.textContent = err.message || '접속을 준비하지 못했어요. 다시 시도해 주세요.';
    password.focus();
  }
});
lock.addEventListener('click', () => {resetSession(); password.focus();});
window.addEventListener('pagehide', resetSession);

'use strict';
// The worker only forwards virtual asset requests to the tab that opened the
// session. Keys live in that tab. A restarted worker rediscovers live tabs.
const scope = new URL(self.registration.scope);
const owners = new Map();
const searching = new Map();
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

function isGate(client) {
  if (!client?.url) return false;
  const url = new URL(client.url);
  return url.origin === scope.origin && (url.pathname === scope.pathname || url.pathname === scope.pathname + 'index.html');
}
self.addEventListener('message', event => {
  const msg = event.data;
  if (!isGate(event.source) || !/^[a-f0-9]{32}$/.test(msg?.token || '')) return;
  if (msg.type === 'open') owners.set(msg.token, event.source.id);
  if (msg.type === 'close' && owners.get(msg.token) === event.source.id) owners.delete(msg.token);
});

function call(client, message, timeout) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {channel.port1.close(); reject(Error('Session unavailable'));}, timeout);
    channel.port1.onmessage = event => {
      clearTimeout(timer);channel.port1.close();resolve(event.data);
    };
    client.postMessage(message, [channel.port2]);
  });
}
async function discover(token) {
  const windows = (await self.clients.matchAll({type: 'window'})).filter(isGate);
  try {
    const client = await Promise.any(windows.map(async windowClient => {
      if (!await call(windowClient, {type: 'probe', token}, 4000)) throw Error('Locked');
      return windowClient;
    }));
    owners.set(token, client.id);
    return client;
  } catch {
    return null;
  }
}
async function owner(token) {
  const id = owners.get(token);
  if (id) {
    const client = await self.clients.get(id);
    if (isGate(client)) return client;
    owners.delete(token);
  }
  if (!searching.has(token)) searching.set(token, discover(token).finally(() => searching.delete(token)));
  return searching.get(token);
}

async function serve(event, token, encodedPath) {
  const request = event.request;
  const headers = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                   'X-Content-Type-Options': 'nosniff', 'X-Robots-Tag': 'noindex, noarchive'};
  if (!['GET', 'HEAD'].includes(request.method)) return new Response(null, {status: 405, headers});
  let path;
  try {path = decodeURIComponent(encodedPath);} catch {return new Response(null, {status: 400, headers});}
  if (path === '' || path.endsWith('/')) path += 'index.html';
  const client = await owner(token);
  if (!client) return new Response(null, {status: 401, headers});
  // The virtual URL is only for this tab's embedded document. An extra tab
  // that knows the URL must still unlock its own session.
  if (request.mode === 'navigate' && request.destination === 'document')
    return new Response(null, {status: 401, headers});
  if (event.clientId && event.clientId !== client.id) {
    const caller = await self.clients.get(event.clientId);
    const prefix = scope.href + 'v/' + token + '/';
    if (!caller?.url.startsWith(prefix)) return new Response(null, {status: 401, headers});
  }
  try {
    const result = await call(client, {type: 'read', token, path}, 60000);
    if (result.status !== 200) return new Response(null, {status: result.status || 503, headers});
    headers['Content-Type'] = result.mime;
    return new Response(request.method === 'HEAD' ? null : result.bytes, {headers});
  } catch {
    return new Response(null, {status: 503, headers});
  }
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname)) return;
  const match = /^v\/([a-f0-9]{32})\/(.*)$/.exec(url.pathname.slice(scope.pathname.length));
  if (match) event.respondWith(serve(event, match[1], match[2]));
});

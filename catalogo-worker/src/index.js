// src/index.js
const slug = (s) => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
const enc = new TextEncoder();
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

async function getToken(env) {
  const sa = JSON.parse(env.GOOGLE_SA_JSON);
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(enc.encode(JSON.stringify({ alg:'RS256', typ:'JWT' })));
  const claim = b64url(enc.encode(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600
  })));
  const pem = sa.private_key.replace(/-----[^-]+-----/g,'').replace(/\s/g,'');
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der,
    { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim));
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: head + '.' + claim + '.' + b64url(sig)
    })
  });
  return (await r.json()).access_token;
}

export default {
  async fetch(req, env, ctx) {
    const cors = { 'Access-Control-Allow-Origin': '*' };
    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: { ...cors, 'Access-Control-Allow-Methods': 'GET' } });
    }
    const cache = caches.default;
    const hit = await cache.match(req);
    if (hit) return hit;

    const token = await getToken(env);
    const url = 'https://sheets.googleapis.com/v4/spreadsheets/' + env.SHEET_ID +
      '/values/' + encodeURIComponent(env.SHEET_RANGE) + '?valueRenderOption=UNFORMATTED_VALUE';
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) return new Response(JSON.stringify({ error: 'sheets_' + r.status }),
      { status: 502, headers: { ...cors, 'Content-Type': 'application/json' } });

    const { values = [] } = await r.json();
    const [head = [], ...rows] = values;
    const cols = head
      .map((h, i) => ({ i, h: String(h).trim() }))
      .filter(c => c.h && !c.h.startsWith('_'));
    const data = rows
      .filter(row => row.some(v => v !== ''))
      .map(row => Object.fromEntries(cols.map(c => [slug(c.h), row[c.i] ?? ''])));

    const res = new Response(JSON.stringify(data), { headers: {
      ...cors, 'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=300'
    }});
    ctx.waitUntil(cache.put(req, res.clone()));
    return res;
  }
};
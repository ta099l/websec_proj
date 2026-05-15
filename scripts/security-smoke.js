const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = process.env.TEST_PORT || 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_FILE = path.join('/tmp', `l33t-store-smoke-${process.pid}.sqlite`);

function request(method, path, body, cookie) {
  return new Promise((resolve, reject) => {
    const data = body ? new URLSearchParams(body).toString() : '';
    const req = http.request(`${BASE}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data),
        Cookie: cookie || ''
      }
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          location: res.headers.location,
          setCookie: res.headers['set-cookie'] || [],
          body: text
        });
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function cookieHeader(jar) {
  return Object.keys(jar).map((key) => `${key}=${jar[key]}`).join('; ');
}

function storeCookies(jar, setCookie) {
  setCookie.forEach((raw) => {
    const first = raw.split(';')[0];
    const index = first.indexOf('=');
    jar[first.slice(0, index)] = first.slice(index + 1);
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function startServer() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['app.js'], {
      cwd: process.cwd(),
      env: { ...process.env, PORT: String(PORT), DB_FILE },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let ready = false;
    const timeout = setTimeout(() => reject(new Error('Server did not start in time')), 8000);
    child.stdout.on('data', (chunk) => {
      if (chunk.toString().includes('L33t Store running')) {
        ready = true;
        clearTimeout(timeout);
        resolve(child);
      }
    });
    child.stderr.on('data', (chunk) => {
      if (!ready) process.stderr.write(chunk);
    });
    child.on('exit', (code) => {
      if (!ready) reject(new Error(`Server exited before tests with code ${code}`));
    });
  });
}

async function main() {
  const server = await startServer();
  try {
    let res = await request('GET', '/', null);
    assert(res.status === 200 && res.body.includes('L33t Store'), 'homepage renders');

    res = await request('GET', '/vulnerable/products', null);
    assert(res.body.includes('name="price_cents"'), 'vulnerable products expose client price field');
    res = await request('GET', '/secure/products', null);
    assert(!res.body.includes('name="price_cents"'), 'secure products hide client price field');

    const vulnCart = {};
    res = await request('POST', '/vulnerable/cart/add', { productId: '1', price_cents: '1', quantity: '-2' }, cookieHeader(vulnCart));
    storeCookies(vulnCart, res.setCookie);
    res = await request('GET', '/vulnerable/cart', null, cookieHeader(vulnCart));
    assert(res.body.includes('$-0.02'), 'vulnerable cart accepts client price and negative quantity');

    const secureCart = {};
    res = await request('POST', '/secure/cart/add', { productId: '1', price_cents: '1', quantity: '-2' }, cookieHeader(secureCart));
    storeCookies(secureCart, res.setCookie);
    res = await request('GET', '/secure/cart', null, cookieHeader(secureCart));
    assert(res.body.includes('$1337.00') && res.body.includes('<td>1</td>'), 'secure cart trusts server price and clamps quantity');

    res = await request('POST', '/vulnerable/login', { username: 'missing', password: 'x', scenario: 'different' });
    assert(res.body.includes('Invalid username'), 'vulnerable login enumerates missing usernames');
    res = await request('POST', '/vulnerable/login', { username: 'wiener', password: 'x', scenario: 'different' });
    assert(res.body.includes('Invalid password'), 'vulnerable login enumerates valid usernames');
    res = await request('POST', '/vulnerable/login', { username: 'missing', password: 'x', scenario: 'subtle' });
    assert(res.body.includes('Invalid login</p>'), 'vulnerable subtle enumeration has no period');
    res = await request('POST', '/vulnerable/login', { username: 'wiener', password: 'x', scenario: 'subtle' });
    assert(res.body.includes('Invalid login.</p>'), 'vulnerable subtle enumeration has period');
    res = await request('POST', '/secure/login', { username: 'missing', password: 'x' });
    assert(res.body.includes('Invalid username or password'), 'secure login returns generic failure');

    const vulnAuth = {};
    res = await request('POST', '/vulnerable/login', { username: 'wiener', password: 'peter', scenario: 'different', remember: '1' }, cookieHeader(vulnAuth));
    storeCookies(vulnAuth, res.setCookie);
    assert(vulnAuth.stayLoggedIn, 'vulnerable remember-me cookie is issued');
    res = await request('GET', '/vulnerable/my-account', null, cookieHeader(vulnAuth));
    assert(res.status === 200 && res.body.includes('wiener'), 'vulnerable 2FA can be skipped after password');
    res = await request('POST', '/vulnerable/2fa', { code: '0000', verify: 'false' }, cookieHeader(vulnAuth));
    assert(res.status === 302 && res.location === '/vulnerable/my-account', 'vulnerable 2FA verify parameter bypass works');

    const secureAuth = {};
    res = await request('POST', '/secure/login', { username: 'wiener', password: 'peter', remember: '1' }, cookieHeader(secureAuth));
    storeCookies(secureAuth, res.setCookie);
    assert(!secureAuth.secureStayLoggedIn, 'secure remember-me is not issued before 2FA');
    res = await request('GET', '/secure/my-account', null, cookieHeader(secureAuth));
    assert(res.status === 302 && res.location === '/secure/login', 'secure account blocks pre-2FA access');
    res = await request('POST', '/secure/2fa', { code: '1337', verify: 'false' }, cookieHeader(secureAuth));
    storeCookies(secureAuth, res.setCookie);
    assert(secureAuth.secureStayLoggedIn, 'secure remember-me is issued after 2FA');

    res = await request('POST', '/secure/change-email', { email: 'blocked@example.test' }, cookieHeader(secureAuth));
    assert(res.status === 403, 'secure change email blocks missing CSRF token');
    res = await request('POST', '/vulnerable/change-email', { email: 'csrf@example.test' }, cookieHeader(vulnAuth));
    assert(res.status === 302, 'vulnerable change email accepts CSRF-style POST');
    res = await request('GET', '/vulnerable/change-email-get?email=csrf-get@example.test', null, cookieHeader(vulnAuth));
    assert(res.status === 302, 'vulnerable change email accepts state-changing GET');
    res = await request('GET', '/secure/change-email-get?email=blocked@example.test', null, cookieHeader(secureAuth));
    assert(res.status === 405, 'secure route blocks state-changing GET');

    console.log('Security smoke tests passed.');
  } finally {
    server.kill();
    if (fs.existsSync(DB_FILE)) fs.unlinkSync(DB_FILE);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new sqlite3.Database(process.env.DB_FILE || path.join(__dirname, 'l33t-store.sqlite'));
const PORT = process.env.PORT || 3000;
const TWO_FA_CODE = '1337';
const vulnerableIpFailures = new Map();
const VULNERABLE_BRUTE_FORCE_LIMIT = 2;
const VULNERABLE_BRUTE_FORCE_BLOCK_MS = 15000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser('l33t-store-demo-secret'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use((req, res, next) => {
  // Teaching-lab convenience: Burp sometimes reuses stale localhost keep-alive
  // connections while the Node dev server is being restarted. Closing each
  // response keeps proxy/browser demos deterministic.
  res.set('Connection', 'close');
  next();
});
app.use(session({
  secret: 'l33t-store-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
  }
}));

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function md5(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function newCsrfToken(req) {
  const token = crypto.randomBytes(24).toString('hex');
  req.session.csrfToken = token;
  return token;
}

function requireCsrf(req, res, next) {
  const sent = req.body.csrf || req.query.csrf;
  if (!sent || !req.session.csrfToken || !timingSafeEqual(sent, req.session.csrfToken)) {
    res.status(403);
    return render(req, res, 'message', {
      title: 'CSRF blocked',
      message: 'The secure route rejected this request because the CSRF token was missing or invalid.'
    });
  }
  return next();
}

async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    locked_until INTEGER DEFAULT 0,
    failed_logins INTEGER DEFAULT 0
  )`);

  await run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price_cents INTEGER NOT NULL
  )`);

  const users = [
    ['wiener', 'wiener@l33t.example', 'peter'],
    ['carlos', 'carlos@l33t.example', 'montoya']
  ];

  for (const [username, email, password] of users) {
    const existing = await get('SELECT id FROM users WHERE username = ?', [username]);
    if (!existing) {
      const hash = await bcrypt.hash(password, 10);
      await run(
        'INSERT INTO users (username, email, password, password_hash) VALUES (?, ?, ?, ?)',
        [username, email, password, hash]
      );
    }
  }

  const existingProducts = await get('SELECT id FROM products LIMIT 1');
  if (!existingProducts) {
    await run(
      'INSERT INTO products (name, description, price_cents) VALUES (?, ?, ?)',
      ['Lightweight l33t leather jacket', 'A premium jacket for elite bug hunters.', 133700]
    );
    await run(
      'INSERT INTO products (name, description, price_cents) VALUES (?, ?, ?)',
      ['Sticker pack', 'Cheap, cheerful, and dangerously collectible.', 99]
    );
    await run(
      'INSERT INTO products (name, description, price_cents) VALUES (?, ?, ?)',
      ['SQLi-proof mug', 'Holds coffee and suspicious payloads.', 1599]
    );
  }
}

function money(cents) {
  return `$${(cents / 100).toFixed(2)}`;
}

function cartCount(cart) {
  return Object.values(cart || {}).reduce((sum, item) => sum + Number(item.quantity), 0);
}

function getMode(req) {
  return req.path.startsWith('/secure') ? 'secure' : 'vulnerable';
}

function render(req, res, view, data = {}) {
  const mode = getMode(req);
  const titles = {
    products: 'Products',
    cart: 'Cart',
    login: 'Log in',
    '2fa': 'Two-factor authentication',
    account: 'My account',
    message: 'L33t Store'
  };
  res.render(view, {
    mode,
    title: data.title || titles[view] || 'L33t Store',
    pathBase: `/${mode}`,
    user: req.session[`${mode}User`] || null,
    cartCount: cartCount(req.session[`${mode}Cart`] || {}),
    money,
    ...data
  });
}

async function currentUser(req, mode) {
  const sessionUser = req.session[`${mode}User`];
  if (!sessionUser) return null;
  return get('SELECT * FROM users WHERE username = ?', [sessionUser.username]);
}

async function hydrateStayLoggedIn(req, mode) {
  if (req.session[`${mode}User`]) return;

  const vulnerableRememberCookie = req.cookies['stay-logged-in'] || req.cookies.stayLoggedIn;
  if (mode === 'vulnerable' && vulnerableRememberCookie) {
    // LAB: Brute-forcing a stay-logged-in cookie VULNERABILITY.
    // This cookie is only base64(username:md5(password)).
    // Anyone who knows or guesses the password hash can forge it without the server secret.
    const decoded = Buffer.from(vulnerableRememberCookie, 'base64').toString('utf8');
    const [username, hash] = decoded.split(':');
    const user = await get('SELECT * FROM users WHERE username = ?', [username]);
    if (user && hash === md5(user.password)) {
      req.session.vulnerableUser = { id: user.id, username: user.username };
    }
  }

  const secureRememberCookie = req.signedCookies['secure-stay-logged-in'] || req.signedCookies.secureStayLoggedIn;
  if (mode === 'secure' && secureRememberCookie) {
    // SECURE PATCH: Brute-forcing a stay-logged-in cookie.
    // The secure route stores a random server-verifiable token in a signed cookie.
    // A real app would persist token hashes per device; this demo keeps it in session state.
    const token = secureRememberCookie;
    if (req.session.secureRememberToken && timingSafeEqual(token, req.session.secureRememberToken)) {
      const user = await get('SELECT * FROM users WHERE username = ?', [req.session.secureRememberUser]);
      if (user) req.session.secureUser = { id: user.id, username: user.username };
    }
  }
}

function requireAuth(mode) {
  return async (req, res, next) => {
    await hydrateStayLoggedIn(req, mode);
    if (!req.session[`${mode}User`]) {
      return res.redirect(`/${mode}/login`);
    }
    return next();
  };
}

function buildCartRows(cart) {
  return Object.values(cart || {}).map((item) => ({
    ...item,
    lineTotal: item.price_cents * item.quantity
  }));
}

function cartTotal(cart) {
  return buildCartRows(cart).reduce((sum, item) => sum + item.lineTotal, 0);
}

app.use(async (req, res, next) => {
  try {
    await hydrateStayLoggedIn(req, getMode(req));
    next();
  } catch (err) {
    next(err);
  }
});

app.get('/', (req, res) => {
  res.render('home', { money });
});

app.get('/vulnerable', (req, res) => res.redirect('/vulnerable/products'));
app.get('/secure', (req, res) => res.redirect('/secure/products'));

app.get('/vulnerable/products', async (req, res, next) => {
  try {
    render(req, res, 'products', { products: await all('SELECT * FROM products') });
  } catch (err) {
    next(err);
  }
});

app.get('/secure/products', async (req, res, next) => {
  try {
    render(req, res, 'products', { products: await all('SELECT * FROM products') });
  } catch (err) {
    next(err);
  }
});

app.post('/vulnerable/cart/add', async (req, res, next) => {
  try {
    const product = await get('SELECT * FROM products WHERE id = ?', [req.body.productId]);
    if (!product) return res.redirect('/vulnerable/products');
    req.session.vulnerableCart = req.session.vulnerableCart || {};
    const id = String(product.id);

    // LAB: Excessive trust in client-side controls VULNERABILITY.
    // Trusts price_cents submitted by the browser.
    // LAB: High-level logic vulnerability VULNERABILITY.
    // Accepts any quantity, including negative values that can reduce the cart total.
    // Learners can lower the price or submit negative quantities to reduce the cart total.
    const price = Number(req.body.price_cents);
    const quantity = Number(req.body.quantity || 1);
    req.session.vulnerableCart[id] = req.session.vulnerableCart[id] || {
      id: product.id,
      name: product.name,
      price_cents: price,
      quantity: 0
    };
    req.session.vulnerableCart[id].price_cents = price;
    req.session.vulnerableCart[id].quantity += quantity;
    res.redirect('/vulnerable/cart');
  } catch (err) {
    next(err);
  }
});

app.post('/secure/cart/add', async (req, res, next) => {
  try {
    const product = await get('SELECT * FROM products WHERE id = ?', [req.body.productId]);
    if (!product) return res.redirect('/secure/products');
    req.session.secureCart = req.session.secureCart || {};
    const id = String(product.id);

    // SECURE PATCH: Excessive trust in client-side controls.
    // SECURE PATCH: High-level logic vulnerability.
    // The secure route ignores client-submitted price and clamps quantity.
    // Product price comes from trusted server-side storage, and negative values are rejected.
    const quantity = Math.max(1, Math.min(10, parseInt(req.body.quantity, 10) || 1));
    req.session.secureCart[id] = req.session.secureCart[id] || {
      id: product.id,
      name: product.name,
      price_cents: product.price_cents,
      quantity: 0
    };
    req.session.secureCart[id].quantity += quantity;
    res.redirect('/secure/cart');
  } catch (err) {
    next(err);
  }
});

app.get('/vulnerable/cart', (req, res) => {
  const cart = req.session.vulnerableCart || {};
  render(req, res, 'cart', { items: buildCartRows(cart), total: cartTotal(cart) });
});

app.get('/secure/cart', (req, res) => {
  const cart = req.session.secureCart || {};
  render(req, res, 'cart', { items: buildCartRows(cart), total: cartTotal(cart) });
});

app.post('/vulnerable/checkout', requireAuth('vulnerable'), (req, res) => {
  const total = cartTotal(req.session.vulnerableCart || {});
  req.session.vulnerableCart = {};
  render(req, res, 'message', {
    title: 'Order placed',
    message: `Vulnerable checkout accepted a total of ${money(total)}.`
  });
});

app.post('/secure/checkout', requireAuth('secure'), (req, res) => {
  const total = cartTotal(req.session.secureCart || {});
  if (total <= 0) {
    // SECURE PATCH: High-level logic vulnerability.
    // Refuses checkout when cart state would produce an empty or invalid total.
    return render(req, res, 'message', {
      title: 'Checkout blocked',
      message: 'The secure checkout refused an empty or invalid cart.'
    });
  }
  req.session.secureCart = {};
  render(req, res, 'message', {
    title: 'Order placed',
    message: `Secure checkout charged the trusted server total of ${money(total)}.`
  });
});

app.get('/vulnerable/login', (req, res) => {
  render(req, res, 'login', { error: null, subtle: null });
});

app.post('/vulnerable/login', async (req, res, next) => {
  try {
    const { username, password, remember, scenario } = req.body;
    let user = await get('SELECT * FROM users WHERE username = ?', [username]);

    if (scenario === 'timing') {
      // LAB: Username enumeration via response timing VULNERABILITY.
      // Only real users reach bcrypt, so valid usernames take noticeably longer.
      if (!user) return render(req, res, 'login', { error: 'Invalid login', subtle: null });
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return render(req, res, 'login', { error: 'Invalid login', subtle: null });
    } else if (scenario === 'lockout') {
      // LAB: Username enumeration via account lock VULNERABILITY.
      // Revealing "account locked" lets attackers enumerate valid accounts.
      if (user && user.locked_until > Date.now()) {
        return render(req, res, 'login', { error: 'This account is locked', subtle: null });
      }
      if (!user) return render(req, res, 'login', { error: 'Invalid username', subtle: null });
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) {
        await run('UPDATE users SET failed_logins = failed_logins + 1, locked_until = CASE WHEN failed_logins + 1 >= 3 THEN ? ELSE locked_until END WHERE id = ?', [Date.now() + 300000, user.id]);
        return render(req, res, 'login', { error: 'Invalid password', subtle: null });
      }
    } else if (scenario === 'broken-bruteforce') {
      // LAB: Broken brute-force protection, IP block VULNERABILITY.
      // This tries to block brute force by IP after 2 failures, but any
      // successful login from the same IP resets the counter. An attacker can alternate
      // "wiener:peter" with guesses for "carlos" to keep the failure count below the limit.
      const ip = req.ip || req.socket.remoteAddress || 'local';
      const entry = vulnerableIpFailures.get(ip) || { failures: 0, blockedUntil: 0 };
      if (entry.blockedUntil > Date.now()) {
        return render(req, res, 'login', { error: 'Too many incorrect logins from your IP. Try again later.', subtle: null });
      }
      if (entry.blockedUntil && entry.blockedUntil <= Date.now()) {
        entry.failures = 0;
        entry.blockedUntil = 0;
      }
      if (entry.failures >= VULNERABLE_BRUTE_FORCE_LIMIT) {
        entry.blockedUntil = Date.now() + VULNERABLE_BRUTE_FORCE_BLOCK_MS;
        vulnerableIpFailures.set(ip, entry);
        return render(req, res, 'login', { error: 'Too many incorrect logins from your IP. Try again later.', subtle: null });
      }
      user = await get('SELECT * FROM users WHERE username = ?', [username.trim().toLowerCase()]);
      if (!user) {
        entry.failures += 1;
        vulnerableIpFailures.set(ip, entry);
        return render(req, res, 'login', { error: 'Invalid username or password', subtle: null });
      }
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) {
        entry.failures += 1;
        vulnerableIpFailures.set(ip, entry);
        return render(req, res, 'login', { error: 'Invalid username or password', subtle: null });
      }
      vulnerableIpFailures.set(ip, { failures: 0, blockedUntil: 0 });
    } else if (scenario === 'subtle') {
      // LAB: Username enumeration via subtly different responses VULNERABILITY.
      // The wording looks generic, but the period reveals whether the username exists.
      if (!user) return render(req, res, 'login', { error: null, subtle: 'Invalid login' });
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return render(req, res, 'login', { error: null, subtle: 'Invalid login.' });
    } else {
      // LAB: Username enumeration via different responses VULNERABILITY.
      // Different messages disclose whether the username exists.
      if (!user) return render(req, res, 'login', { error: 'Invalid username', subtle: null });
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return render(req, res, 'login', { error: 'Invalid password', subtle: null });
    }

    req.session.pendingVulnerable2fa = user.username;

    // LAB: 2FA simple bypass VULNERABILITY.
    // The app marks the user logged in before 2FA is complete.
    // A learner can pass the password step, skip /vulnerable/2fa, and browse directly to /vulnerable/my-account.
    req.session.vulnerableUser = { id: user.id, username: user.username };

    if (remember && user) {
      // LAB: Brute-forcing a stay-logged-in cookie VULNERABILITY.
      // Weak stay-logged-in cookie: base64(username:md5(password)).
      res.cookie('stay-logged-in', Buffer.from(`${user.username}:${md5(user.password)}`).toString('base64'), {
        httpOnly: true,
        sameSite: 'lax'
      });
    }
    res.redirect('/vulnerable/2fa');
  } catch (err) {
    next(err);
  }
});

app.get('/secure/login', (req, res) => {
  render(req, res, 'login', { error: null, subtle: null });
});

app.post('/secure/login', async (req, res, next) => {
  try {
    const { username, password, remember } = req.body;
    const normalizedUsername = username.trim().toLowerCase();
    const user = await get('SELECT * FROM users WHERE username = ?', [normalizedUsername]);
    const fakeHash = '$2b$10$w1TzW3cJ3IwdbBgL2M6PrumVnI6NnVkgw6x1vVEFqF40X8r/ZbSzu';
    const hashToCheck = user ? user.password_hash : fakeHash;
    req.session.secureFailures = req.session.secureFailures || {};
    const failureKey = normalizedUsername;

    // SECURE PATCH: Username enumeration via different responses.
    // SECURE PATCH: Username enumeration via subtly different responses.
    // SECURE PATCH: Username enumeration via response timing.
    // SECURE PATCH: Username enumeration via account lock.
    // The secure route uses one generic failure and runs bcrypt for missing users too,
    // reducing username enumeration by response text, subtle text, timing, and lockout behavior.
    const ok = await bcrypt.compare(password, hashToCheck);
    if (req.session.secureFailures[failureKey] >= 5 || !user || !ok || user.locked_until > Date.now()) {
      // SECURE PATCH: Broken brute-force protection, IP block.
      // Brute-force protection is keyed to a normalized identity and uses the same
      // generic response as every other login failure.
      req.session.secureFailures[failureKey] = (req.session.secureFailures[failureKey] || 0) + 1;
      return render(req, res, 'login', { error: 'Invalid username or password', subtle: null });
    }
    req.session.secureFailures[failureKey] = 0;

    req.session.pendingSecure2fa = user.username;
    req.session.pendingSecureRemember = Boolean(remember);
    if (remember) {
      // SECURE PATCH: 2FA simple bypass.
      // SECURE PATCH: Brute-forcing a stay-logged-in cookie.
      // Remember-me is recorded as intent only until 2FA succeeds.
      // Issuing this cookie before 2FA would let it become a 2FA bypass.
    }
    res.redirect('/secure/2fa');
  } catch (err) {
    next(err);
  }
});

app.get('/vulnerable/2fa', (req, res) => {
  // LAB: 2FA simple bypass VULNERABILITY.
  // Visiting /vulnerable/my-account directly only checks the main session user.
  // This page sets no robust "2FA required" gate for all protected pages.
  render(req, res, '2fa', { error: null, code: TWO_FA_CODE });
});

app.post('/vulnerable/2fa', async (req, res, next) => {
  try {
    const username = req.session.pendingVulnerable2fa;
    if (!username) return res.redirect('/vulnerable/login');
    const user = await get('SELECT * FROM users WHERE username = ?', [username]);

    // LAB: 2FA broken logic VULNERABILITY.
    // The verify parameter decides whether the code is checked.
    // Posting verify=false or omitting normal verification lets the attacker skip 2FA.
    if (req.body.verify === 'false' || req.body.code === TWO_FA_CODE) {
      req.session.vulnerableUser = { id: user.id, username: user.username };
      delete req.session.pendingVulnerable2fa;
      return res.redirect('/vulnerable/my-account');
    }

    return render(req, res, '2fa', { error: 'Invalid 2FA code', code: TWO_FA_CODE });
  } catch (err) {
    next(err);
  }
});

app.get('/secure/2fa', (req, res) => {
  render(req, res, '2fa', { error: null, code: TWO_FA_CODE });
});

app.post('/secure/2fa', async (req, res, next) => {
  try {
    const username = req.session.pendingSecure2fa;
    if (!username) return res.redirect('/secure/login');

    // SECURE PATCH: 2FA simple bypass.
    // SECURE PATCH: 2FA broken logic.
    // The secure route ignores client-supplied control parameters and validates only
    // the server-issued pending 2FA challenge plus the expected code.
    if (req.body.code !== TWO_FA_CODE) {
      return render(req, res, '2fa', { error: 'Invalid 2FA code', code: TWO_FA_CODE });
    }

    const user = await get('SELECT * FROM users WHERE username = ?', [username]);
    req.session.secureUser = { id: user.id, username: user.username };
    delete req.session.pendingSecure2fa;
    if (req.session.pendingSecureRemember) {
      // SECURE PATCH: Brute-forcing a stay-logged-in cookie.
      // Use a random signed token instead of a forgeable password-derived cookie,
      // and issue it only after the second factor is complete.
      const token = crypto.randomBytes(32).toString('hex');
      req.session.secureRememberToken = token;
      req.session.secureRememberUser = user.username;
      res.cookie('secure-stay-logged-in', token, {
        httpOnly: true,
        sameSite: 'lax',
        signed: true
      });
    }
    delete req.session.pendingSecureRemember;
    res.redirect('/secure/my-account');
  } catch (err) {
    next(err);
  }
});

app.get('/vulnerable/my-account', requireAuth('vulnerable'), async (req, res, next) => {
  try {
    const user = await currentUser(req, 'vulnerable');
    render(req, res, 'account', { account: user, csrfToken: null });
  } catch (err) {
    next(err);
  }
});

app.get('/secure/my-account', requireAuth('secure'), async (req, res, next) => {
  try {
    const user = await currentUser(req, 'secure');
    render(req, res, 'account', { account: user, csrfToken: newCsrfToken(req) });
  } catch (err) {
    next(err);
  }
});

app.post('/vulnerable/change-email', requireAuth('vulnerable'), async (req, res, next) => {
  try {
    // LAB: CSRF vulnerability with no defenses VULNERABILITY.
    // No CSRF token is required, so another site can force a logged-in
    // user's browser to POST this form.
    await run('UPDATE users SET email = ? WHERE username = ?', [req.body.email, req.session.vulnerableUser.username]);
    res.redirect('/vulnerable/my-account');
  } catch (err) {
    next(err);
  }
});

app.post('/secure/change-email', requireAuth('secure'), requireCsrf, async (req, res, next) => {
  try {
    // SECURE PATCH: CSRF vulnerability with no defenses.
    // The secure route requires a per-session CSRF token on state-changing requests.
    await run('UPDATE users SET email = ? WHERE username = ?', [req.body.email, req.session.secureUser.username]);
    res.redirect('/secure/my-account');
  } catch (err) {
    next(err);
  }
});

app.get('/vulnerable/change-email-get', requireAuth('vulnerable'), async (req, res, next) => {
  try {
    // LAB: CSRF where token validation depends on request method VULNERABILITY.
    // This route pretends token validation is a POST-only concern, so GET still
    // changes account state and can be triggered by an image tag or link.
    await run('UPDATE users SET email = ? WHERE username = ?', [req.query.email, req.session.vulnerableUser.username]);
    res.redirect('/vulnerable/my-account');
  } catch (err) {
    next(err);
  }
});

app.get('/secure/change-email-get', requireAuth('secure'), (req, res) => {
  // SECURE PATCH: CSRF where token validation depends on request method.
  // The secure route refuses state changes over GET entirely.
  res.status(405);
  render(req, res, 'message', {
    title: 'Method not allowed',
    message: 'Secure routes do not change email addresses with GET requests.'
  });
});

app.post('/vulnerable/logout', (req, res) => {
  delete req.session.vulnerableUser;
  res.clearCookie('stay-logged-in');
  res.clearCookie('stayLoggedIn');
  res.redirect('/vulnerable/products');
});

app.post('/secure/logout', (req, res) => {
  delete req.session.secureUser;
  delete req.session.secureRememberToken;
  delete req.session.secureRememberUser;
  res.clearCookie('secure-stay-logged-in');
  res.clearCookie('secureStayLoggedIn');
  res.redirect('/secure/products');
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('L33t Store error');
});

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`L33t Store running at http://127.0.0.1:${PORT}`);
  });
}).catch((err) => {
  console.error(err);
  process.exit(1);
});

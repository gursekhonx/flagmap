// Fixture for signed_cookie_guard.py (v1.53.0). Mirrors LA CTF 2026
// "clawcha": a username the client picks becomes a signed cookie, read
// back through cookie-parser's signedCookies (which JSON-decodes "j:").
app.use(cookieParser(secret));
app.use((req, res, next) => {
  if (typeof req.signedCookies.username === 'string') res.locals.user = users.get(req.signedCookies.username);
  next();
});
app.post('/login', (req, res) => {
  const username = req.body.username;
  users.set(username, { username, owner: false });
  res.cookie('username', username, { signed: true }).json({ ok: true });  // ruleid: Weak Auth Logic
});

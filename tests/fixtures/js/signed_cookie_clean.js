// Safe: the signed cookie carries a server-generated session id, and an
// unsigned cookie with a user value isn't this check's business.
app.use(cookieParser(secret));
app.post('/login', (req, res) => {
  const { username } = req.body;
  const sid = crypto.randomBytes(16).toString('hex');
  sessions.set(sid, username);
  res.cookie('sid', sid, { signed: true, httpOnly: true });  // safe: Weak Auth Logic
  res.cookie('lastUser', username, { httpOnly: true });  // safe: Weak Auth Logic
  if (req.signedCookies.sid) res.json({ ok: true });
});

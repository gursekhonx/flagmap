// log_message_guard.py's motivating shape (see its module docstring,
// found against WebGoat's lessons/passwordstorage/js/password-
// storage.js): a console.error() call whose MESSAGE STRING happens to
// contain a sensitive-sounding word, with no actual sensitive value
// anywhere in the call at all.
function loadTrainingData() {
  return Promise.all([]).catch((error) =>
    console.error("Unable to load password storage training data", error));  // safe: Sensitive Data Exposure in Logs
}

// The real bug this rule exists to catch: a genuine variable sitting
// outside any string, right alongside the message — must still fire.
function logLoginAttempt(password) {
  console.log("login attempt with password:", password);  // ruleid: Sensitive Data Exposure in Logs
}

// A sensitive value reaching the log via template-literal interpolation
// rather than a second argument — the interpolated identifier survives
// log_message_guard.py's strip (only the surrounding literal text is
// dropped), so this must also still fire.
function logToken(token) {
  console.log(`issued token: ${token}`);  // ruleid: Sensitive Data Exposure in Logs
}

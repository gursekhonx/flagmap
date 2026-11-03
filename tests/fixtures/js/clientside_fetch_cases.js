// ssrf_fetch_guard.py's motivating shape (see its module docstring,
// found against WebGoat's lessons/webauthn/js/webauthn.js and lessons/
// securitymisconfiguration/js/security-misconfiguration-task2.js): a
// plain browser script that calls fetch() with a URL held in a local
// variable. There is no SSRF concept here at all — this file never
// handles an HTTP request on a server's behalf, it's the browser making
// its own outbound call, same trust boundary as any other page asset it
// loads. This file deliberately contains none of the signals
// is_clientside_js() scans for (no short-form request-handling object
// access, no server-framework import, no route-registration call
// anywhere), so it's unambiguously client-side. (Careful: don't spell
// any of those trigger shapes out literally in this prose, or this
// fixture would self-match the very signal it's demonstrating the
// absence of.)

function loadStatus(url) {
  return fetch(url, { method: 'GET' }).then(function (response) {  // safe: SSRF (Server-Side Request Forgery)
    return response.json();
  });
}

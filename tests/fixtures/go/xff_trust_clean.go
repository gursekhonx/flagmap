// Safe counterpart to xff_trust_vuln.go: the forwarding header is read,
// but only for logging — nothing in this file compares any IP to a literal
// or an allowlist, so the second signal never fires. Not meant to compile.
package main

func logRequest(r *http.Request) {
	clientIP := r.Header.Get("X-Forwarded-For")  // safe: Weak Auth Logic
	log.Printf("request from %s to %s", clientIP, r.URL.Path)
}

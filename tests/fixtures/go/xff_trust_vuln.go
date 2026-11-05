// Fixture for xff_trust_guard.py (v1.36.0) — a standalone file because the
// check needs two signals from the WHOLE file: a read of the client-IP
// forwarding header, and an IP-allowlist decision. Mirrors DownUnderCTF
// 2023's real "proxed"/"actually-proxed" secret_server almost verbatim.
// Not meant to compile.
package main

func handler(w http.ResponseWriter, r *http.Request) {
	xff := r.Header.Values("X-Forwarded-For")  // ruleid: Weak Auth Logic
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if xff != nil {
		ips := strings.Split(xff[len(xff)-1], ", ")
		ip = ips[len(ips)-1]
	}
	if ip != "31.33.33.7" {
		http.Error(w, "untrusted IP", http.StatusForbidden)
		return
	}
	w.Write([]byte(os.Getenv("FLAG")))
}

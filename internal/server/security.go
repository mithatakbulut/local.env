package server

import (
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// requestLimiter is intentionally process-local: v1 deploys one server
// container and does not introduce Redis or a distributed coordination layer.
// It stores only a keyed hash of a presented bearer token, never the token.
type requestLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

type rateWindow struct {
	started time.Time
	count   int
}

func newRequestLimiter() *requestLimiter {
	return &requestLimiter{windows: make(map[string]rateWindow)}
}

func (l *requestLimiter) allow(category, key string, maximum int, duration time.Duration, now time.Time) bool {
	if maximum <= 0 || key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	compound := category + ":" + key
	window := l.windows[compound]
	if window.started.IsZero() || now.Sub(window.started) >= duration {
		l.windows[compound] = rateWindow{started: now, count: 1}
		return true
	}
	if window.count >= maximum {
		return false
	}
	window.count++
	l.windows[compound] = window
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (s *Server) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, s.config.PublicURL != nil && s.config.PublicURL.Scheme == "https")
		requestID := requestID(r)
		w.Header().Set("X-Request-ID", requestID)
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}

		if unsafeMethod(r.Method) && r.URL.Path != "/api/v1/github/webhook" && s.rejectCrossOrigin(r) {
			http.Error(recorder, "cross-origin request rejected", http.StatusForbidden)
			s.logRequest(requestID, r, recorder.status, started)
			return
		}
		if category, maximum, period, limited := requestRate(r); limited && !s.limiter.allow(category, rateLimitKey(r), maximum, period, started) {
			recorder.Header().Set("Retry-After", strconv.Itoa(int(period.Seconds())))
			http.Error(recorder, "request rate limit exceeded", http.StatusTooManyRequests)
			s.logRequest(requestID, r, recorder.status, started)
			return
		}
		next.ServeHTTP(recorder, r)
		s.logRequest(requestID, r, recorder.status, started)
	})
}

func setSecurityHeaders(w http.ResponseWriter, https bool) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://github.com; object-src 'none'; style-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	// no-referrer makes Chromium emit Origin: null for ordinary HTML form POSTs,
	// which prevents the same-origin setup form from satisfying CSRF origin
	// validation. Keep referrers off every cross-origin navigation while allowing
	// the application to identify its own same-origin form submissions.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	if https {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func unsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func requestRate(r *http.Request) (string, int, time.Duration, bool) {
	if r.URL.Path == "/api/v1/github/webhook" {
		return "", 0, 0, false // Signature validation is the public ingress control.
	}
	if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/login" || r.URL.Path == "/api/v1/auth/exchange" {
		return "auth", 20, 5 * time.Minute, true
	}
	if strings.Contains(r.URL.Path, "/snapshot") || strings.HasSuffix(r.URL.Path, "/pulls/current") {
		return "snapshot", 240, time.Minute, true
	}
	if unsafeMethod(r.Method) && strings.HasPrefix(r.URL.Path, "/api/") {
		return "mutation", 60, time.Minute, true
	}
	return "", 0, 0, false
}

func rateLimitKey(r *http.Request) string {
	if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
		sum := sha256.Sum256([]byte(strings.TrimPrefix(authorization, "Bearer ")))
		return "token:" + base64.RawURLEncoding.EncodeToString(sum[:])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return "ip:" + host
	}
	if r.RemoteAddr != "" {
		return "ip:" + r.RemoteAddr
	}
	return "ip:unknown"
}

func requestID(r *http.Request) string {
	// Never reflect a caller-supplied correlation value into logs or responses.
	sum := sha256.Sum256([]byte(time.Now().UTC().String() + r.Method + r.URL.Path))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func (s *Server) logRequest(requestID string, r *http.Request, status int, started time.Time) {
	if status == 0 {
		status = http.StatusOK
	}
	s.logger.Info("http request completed", "request_id", requestID, "method", r.Method, "status", status, "latency_ms", time.Since(started).Milliseconds())
}

func defaultLogger() *slog.Logger { return slog.Default() }

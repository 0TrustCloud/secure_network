package secure_network

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

type dbscSessionRecord struct {
	Username   string `json:"username"`
	DBSCPubKey string `json:"dbsc_pub_key,omitempty"`
}

func requestOrigin(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "http" {
		scheme = "http"
	}
	return scheme + "://" + strings.ToLower(host)
}

// dbscIncludeSiteAllowed reports whether DBSC scope.include_site may be true.
// Spec (W3C DBSC): include_site can only be true if the origin host is the root
// eTLD+1 (registrable domain). Subdomains of 0trust.cloud must use false.
func dbscIncludeSiteAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	// Known apex product / platform domains we operate.
	switch host {
	case "0trust.cloud", "0trust.services", "0trust.social", "0trust.name", "0trust.codes",
		"williwaw.app", "motionkb.com", "defcon.chat", "bandy.chat", "tunneltug.com":
		return true
	}
	// Conservative: only bare two-label hosts (example.com). Multi-label faces
	// (defcon.0trust.cloud, social.0trust.cloud) are never eTLD+1.
	parts := strings.Split(host, ".")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func readRegistrationJWT(r *http.Request) (string, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return "", nil
	}
	if strings.HasPrefix(raw, "{") {
		var wrap struct {
			JWT string `json:"jwt"`
		}
		if json.Unmarshal(body, &wrap) == nil && wrap.JWT != "" {
			return wrap.JWT, nil
		}
	}
	return raw, nil
}

func jwkFromRegistrationJWT(jwtStr string) (string, error) {
	if jwtStr == "" {
		return "", nil
	}
	token, _, err := new(jwt.Parser).ParseUnverified(jwtStr, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	jwkBytes, err := json.Marshal(token.Header["jwk"])
	if err != nil {
		return "", err
	}
	return string(jwkBytes), nil
}

func (r *Router) loadDBSCSession(jti string) (dbscSessionRecord, bool) {
	var rec dbscSessionRecord
	if r.SdfEngine == nil {
		return rec, false
	}
	txn := r.SdfEngine.Store.Begin()
	raw, err := r.SdfEngine.Store.Get(txn, []byte("data:session:"+jti))
	txn.Commit()
	if err != nil || len(raw) == 0 {
		return rec, false
	}
	if json.Unmarshal(raw, &rec) != nil {
		return rec, false
	}
	return rec, true
}

func (r *Router) saveDBSCSession(jti string, rec dbscSessionRecord, ttl time.Duration) {
	if r.SdfEngine == nil {
		return
	}
	raw, _ := json.Marshal(rec)
	txn := r.SdfEngine.Store.Begin()
	_ = r.SdfEngine.Store.Put(txn, []byte("data:session:"+jti), raw, ttl)
	_ = txn.Commit()
}

func (r *Router) handleStartSession(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := req.Cookie(r.TargetCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "No active session", http.StatusUnauthorized)
		return
	}

	subject, err := r.SessionManager.ValidateCookieToken(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	jti, err := r.SessionManager.ExtractJTI(cookie.Value)
	if err != nil {
		http.Error(w, "Malformed session", http.StatusUnauthorized)
		return
	}

	jwtStr, _ := readRegistrationJWT(req)
	jwkJSON, _ := jwkFromRegistrationJWT(jwtStr)

	rec := dbscSessionRecord{Username: subject}
	if existing, ok := r.loadDBSCSession(jti); ok && existing.Username != "" {
		rec.Username = existing.Username
	}
	if jwkJSON != "" {
		rec.DBSCPubKey = jwkJSON
	}
	r.saveDBSCSession(jti, rec, 24*time.Hour)

	origin := requestOrigin(req)
	host := ""
	if u, err := url.Parse(origin); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	// W3C DBSC: include_site may only be true when origin host is the registrable
	// domain (eTLD+1). Product faces like defcon.0trust.cloud must use false or
	// Chrome rejects session creation with "Invalid include_site in scope".
	includeSite := dbscIncludeSiteAllowed(host)

	domain := getDBSCDomain(r.RouteMap, req)
	if domain == "" {
		domain = host
	}
	// When scope is origin-only, cookie Domain must stay on this host (not parent).
	if !includeSite && host != "" {
		domain = host
	}

	shortCookie := &http.Cookie{
		Name:     r.TargetCookie,
		Value:    cookie.Value,
		MaxAge:   600,
		Domain:   domain,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, shortCookie)

	cookieAttrs := "Secure; HttpOnly; SameSite=Lax; Path=/"
	if domain != "" {
		cookieAttrs = "Domain=" + domain + "; " + cookieAttrs
	}

	cfg := map[string]interface{}{
		"session_identifier": jti,
		"refresh_url":        "/RefreshEndpoint",
		"scope": map[string]interface{}{
			"origin":       origin,
			"include_site": includeSite,
		},
		"credentials": []map[string]string{{
			"type":       "cookie",
			"name":       r.TargetCookie,
			"attributes": cookieAttrs,
		}},
	}

	if r.Logger != nil {
		r.Logger.Audit(subject, "DBSC_START_SESSION", "DBSC session registered for "+origin)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (r *Router) handleRefreshEndpoint(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := req.Header.Get("Sec-Secure-Session-Id")
	if sessionID == "" {
		sessionID = req.Header.Get("Sec-Session-Id")
	}

	cookie, err := req.Cookie(r.TargetCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "Session missing", http.StatusUnauthorized)
		return
	}

	jti, err := r.SessionManager.ExtractJTI(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session token", http.StatusUnauthorized)
		return
	}
	if sessionID != "" && sessionID != jti {
		http.Error(w, "Session id mismatch", http.StatusUnauthorized)
		return
	}

	rec, ok := r.loadDBSCSession(jti)
	if !ok || rec.DBSCPubKey == "" {
		http.Error(w, "Session not DBSC-bound", http.StatusBadRequest)
		return
	}

	responseHeader := req.Header.Get("Secure-Session-Response")
	if responseHeader == "" {
		responseHeader = req.Header.Get("Sec-Session-Response")
	}

	if responseHeader == "" {
		w.Header().Set("Secure-Session-Challenge", `"`+jti+`-`+time.Now().Format("150405")+`"`)
		http.Error(w, "Challenge required", http.StatusForbidden)
		return
	}

	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(rec.DBSCPubKey)); err != nil {
		http.Error(w, "Invalid stored DBSC key", http.StatusInternalServerError)
		return
	}

	token, err := jwt.Parse(responseHeader, func(token *jwt.Token) (interface{}, error) {
		return jwk.Key, nil
	})
	if err != nil || token == nil || !token.Valid {
		http.Error(w, "Invalid DBSC response", http.StatusForbidden)
		return
	}

	domain := getDBSCDomain(r.RouteMap, req)
	refreshed := &http.Cookie{
		Name:     r.TargetCookie,
		Value:    cookie.Value,
		MaxAge:   600,
		Domain:   domain,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, refreshed)
	w.Header().Add("Set-Cookie", refreshed.String()+"; Sec-Provided-Session-Key")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"refreshed"}`))

	if r.Logger != nil {
		r.Logger.Audit(rec.Username, "DBSC_REFRESH", "session refreshed")
	}
}
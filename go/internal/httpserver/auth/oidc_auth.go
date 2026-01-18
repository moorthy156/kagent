package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	kagentauth "github.com/kagent-dev/kagent/go/pkg/auth"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName  = "kagent_session"
	oidcStateCookie    = "kagent_oidc_state"
	oidcNonceCookie    = "kagent_oidc_nonce"
	oidcVerifierCookie = "kagent_oidc_verifier"
)

type InteractiveAuthProvider interface {
	kagentauth.AuthProvider
	HandleLogin(w http.ResponseWriter, r *http.Request)
	HandleCallback(w http.ResponseWriter, r *http.Request)
	HandleLogout(w http.ResponseWriter, r *http.Request)
}

type OIDCAuthenticator struct {
	provider       *oidc.Provider
	verifier       *oidc.IDTokenVerifier
	oauth2Config   *oauth2.Config
	usernameClaim  string
	groupsClaim    string
	sessionSecret  []byte
	cookieDomain   string
	cookieSecure   bool
	cookieSameSite http.SameSite
}

type oidcClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
	Nonce             string   `json:"nonce"`
}

type sessionClaims struct {
	UserID string   `json:"uid"`
	Groups []string `json:"groups"`
	jwt.RegisteredClaims
}

func NewOIDCAuthenticatorFromEnv(ctx context.Context) (*OIDCAuthenticator, error) {
	issuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL"))
	clientID := strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET"))
	redirectURL := strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL"))
	secret := os.Getenv("AUTH_SESSION_SECRET")

	if issuer == "" || clientID == "" || redirectURL == "" || secret == "" {
		return nil, fmt.Errorf("missing required env vars: OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_REDIRECT_URL, AUTH_SESSION_SECRET")
	}

	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider init failed: %w", err)
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       parseScopes(os.Getenv("OIDC_SCOPES")),
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	usernameClaim := strings.TrimSpace(os.Getenv("OIDC_USERNAME_CLAIM"))
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	groupsClaim := strings.TrimSpace(os.Getenv("OIDC_GROUPS_CLAIM"))
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	cookieDomain := strings.TrimSpace(os.Getenv("AUTH_COOKIE_DOMAIN"))
	cookieSecure := strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_COOKIE_SECURE")), "true")
	cookieSameSite := http.SameSiteLaxMode
	if strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_COOKIE_SAMESITE")), "strict") {
		cookieSameSite = http.SameSiteStrictMode
	}

	return &OIDCAuthenticator{
		provider:       p,
		verifier:       p.Verifier(&oidc.Config{ClientID: clientID}),
		oauth2Config:   cfg,
		usernameClaim:  usernameClaim,
		groupsClaim:    groupsClaim,
		sessionSecret:  []byte(secret),
		cookieDomain:   cookieDomain,
		cookieSecure:   cookieSecure,
		cookieSameSite: cookieSameSite,
	}, nil
}

func parseScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (a *OIDCAuthenticator) Authenticate(ctx context.Context, reqHeaders http.Header, query url.Values) (kagentauth.Session, error) {
	cookieHeader := reqHeaders.Get("Cookie")
	if cookieHeader == "" {
		return nil, errors.New("no session")
	}

	req := &http.Request{Header: reqHeaders}
	c, err := req.Cookie(sessionCookieName)
	if err != nil || c == nil || strings.TrimSpace(c.Value) == "" {
		return nil, errors.New("no session")
	}

	claims := &sessionClaims{}
	tok, err := jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.sessionSecret, nil
	})
	if err != nil || tok == nil || !tok.Valid {
		return nil, errors.New("invalid session")
	}

	return &SimpleSession{
		P: kagentauth.Principal{
			User: kagentauth.User{ID: claims.UserID, Roles: claims.Groups},
		},
	}, nil
}

func (a *OIDCAuthenticator) UpstreamAuth(r *http.Request, session kagentauth.Session, upstreamPrincipal kagentauth.Principal) error {
	if session == nil {
		return nil
	}
	p := session.Principal()
	if p.User.ID != "" {
		r.Header.Set("X-User-Id", p.User.ID)
	}
	return nil
}

func (a *OIDCAuthenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomURLSafe(32)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}
	verifier, err := randomURLSafe(64)
	if err != nil {
		http.Error(w, "failed to generate verifier", http.StatusInternalServerError)
		return
	}
	challenge := codeChallengeS256(verifier)

	setTempCookie(w, oidcStateCookie, state, a.cookieDomain, a.cookieSecure, a.cookieSameSite)
	setTempCookie(w, oidcNonceCookie, nonce, a.cookieDomain, a.cookieSecure, a.cookieSameSite)
	setTempCookie(w, oidcVerifierCookie, verifier, a.cookieDomain, a.cookieSecure, a.cookieSameSite)

	redirectTo := r.URL.Query().Get("redirect")
	if redirectTo == "" {
		redirectTo = "/"
	}
	setTempCookie(w, "kagent_post_login_redirect", redirectTo, a.cookieDomain, a.cookieSecure, a.cookieSameSite)

	authURL := a.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusFound)
}

func (a *OIDCAuthenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	expectedState, err := readCookie(r, oidcStateCookie)
	if err != nil || expectedState != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	nonce, err := readCookie(r, oidcNonceCookie)
	if err != nil || nonce == "" {
		http.Error(w, "missing nonce", http.StatusBadRequest)
		return
	}
	verifier, err := readCookie(r, oidcVerifierCookie)
	if err != nil || verifier == "" {
		http.Error(w, "missing verifier", http.StatusBadRequest)
		return
	}

	oauth2Token, err := a.oauth2Config.Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "missing id_token", http.StatusUnauthorized)
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	var claimsMap map[string]any
	if err := idToken.Claims(&claimsMap); err != nil {
		http.Error(w, "failed to parse claims", http.StatusUnauthorized)
		return
	}

	if claimNonce, _ := claimsMap["nonce"].(string); claimNonce != "" && claimNonce != nonce {
		http.Error(w, "invalid nonce", http.StatusUnauthorized)
		return
	}

	userID := extractStringClaim(claimsMap, a.usernameClaim)
	if userID == "" {
		userID = extractStringClaim(claimsMap, "email")
	}
	if userID == "" {
		userID = idToken.Subject
	}

	groups := extractStringSliceClaim(claimsMap, a.groupsClaim)

	jwtTok := jwt.NewWithClaims(jwt.SigningMethodHS256, &sessionClaims{
		UserID: userID,
		Groups: groups,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Hour)),
			Subject:   userID,
		},
	})
	signed, err := jwtTok.SignedString(a.sessionSecret)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signed,
		Path:     "/",
		Domain:   a.cookieDomain,
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: a.cookieSameSite,
		Expires:  time.Now().Add(12 * time.Hour),
	})

	clearCookie(w, oidcStateCookie, a.cookieDomain)
	clearCookie(w, oidcNonceCookie, a.cookieDomain)
	clearCookie(w, oidcVerifierCookie, a.cookieDomain)

	redirectTo, _ := readCookie(r, "kagent_post_login_redirect")
	if redirectTo == "" {
		redirectTo = "/"
	}
	clearCookie(w, "kagent_post_login_redirect", a.cookieDomain)

	w.Header().Set("Location", redirectTo)
	w.WriteHeader(http.StatusFound)
}

func (a *OIDCAuthenticator) HandleLogout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, sessionCookieName, a.cookieDomain)
	w.WriteHeader(http.StatusNoContent)
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func codeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func setTempCookie(w http.ResponseWriter, name, value, domain string, secure bool, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		Expires:  time.Now().Add(10 * time.Minute),
	})
}

func clearCookie(w http.ResponseWriter, name, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func readCookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func extractStringClaim(m map[string]any, key string) string {
	if key == "" {
		return ""
	}
	if v, ok := m[key]; ok {
		s, _ := v.(string)
		return s
	}
	return ""
}

func extractStringSliceClaim(m map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}

	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, it := range vv {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if vv == "" {
			return nil
		}
		var arr []string
		if err := json.Unmarshal([]byte(vv), &arr); err == nil {
			return arr
		}
		parts := strings.Split(vv, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	default:
		return nil
	}
}

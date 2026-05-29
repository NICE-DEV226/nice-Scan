package hacker

import (
	"net/http"
	"sync"
)

type SessionManager struct {
	mu       sync.RWMutex
	cookies  []*http.Cookie
	headers  map[string]string
	tokens   []string
	activeJWT string
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		headers: make(map[string]string),
	}
}

func (sm *SessionManager) AddCookies(cookies []*http.Cookie) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, c := range cookies {
		if c.Value == "" {
			continue
		}
		existing := false
		for i, existingCookie := range sm.cookies {
			if existingCookie.Name == c.Name && existingCookie.Domain == c.Domain {
				sm.cookies[i] = c
				existing = true
				break
			}
		}
		if !existing {
			sm.cookies = append(sm.cookies, c)
		}
	}
}

func (sm *SessionManager) SetHeader(key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.headers[key] = value
}

func (sm *SessionManager) AddToken(tok string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, t := range sm.tokens {
		if t == tok {
			return
		}
	}
	sm.tokens = append(sm.tokens, tok)
	if len(sm.tokens) == 1 {
		sm.activeJWT = tok
	}
}

func (sm *SessionManager) SetActiveJWT(tok string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.activeJWT = tok
}

func (sm *SessionManager) GetActiveJWT() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeJWT
}

func (sm *SessionManager) HasSession() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.cookies) > 0 || len(sm.tokens) > 0
}

func (sm *SessionManager) Apply(req *http.Request) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, c := range sm.cookies {
		req.AddCookie(c)
	}
	for k, v := range sm.headers {
		req.Header.Set(k, v)
	}
	if sm.activeJWT != "" {
		req.Header.Set("Authorization", "Bearer "+sm.activeJWT)
	}
}

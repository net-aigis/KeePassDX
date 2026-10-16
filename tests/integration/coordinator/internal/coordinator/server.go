// Package coordinator implements a single-instance, encrypted-blob KDBX
// coordinator. It cannot decrypt passwords and never parses a KDBX file.
package coordinator

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxBody = int64(2 << 30) // 2 GiB: configurable later, not entire-memory buffering
const leaseDuration = 90 * time.Second

type lease struct {
	token   string
	owner   string
	expires time.Time
}

type Server struct {
	mu     sync.Mutex
	dir    string
	secret string
	leases map[string]lease
	now    func() time.Time
}

type LockResponse struct {
	Token    string `json:"token"`
	Expires  string `json:"expires"`
	Revision string `json:"revision"`
}

func New(dir, secret string) (*Server, error) {
	if len(secret) < 32 {
		return nil, errors.New("access token must contain at least 32 characters")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	return &Server{dir: dir, secret: secret, leases: make(map[string]lease), now: time.Now}, nil
}

func validName(s string) bool {
	if len(s) < 1 || len(s) > 96 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(s.secret)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Exact paths, no untrusted filepath fragments.
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) != 4 || segments[0] != "v1" || segments[1] != "databases" || !validName(segments[2]) {
		http.NotFound(w, r)
		return
	}
	id, action := segments[2], segments[3]
	switch action {
	case "lock":
		switch r.Method {
		case http.MethodPost:
			s.acquire(w, r, id)
		case http.MethodDelete:
			s.release(w, r, id)
		default:
			http.Error(w, "method not allowed", 405)
		}
	case "renew":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		s.renew(w, r, id)
	case "file":
		switch r.Method {
		case http.MethodGet:
			s.download(w, r, id)
		case http.MethodPut:
			s.publish(w, r, id)
		default:
			http.Error(w, "method not allowed", 405)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) file(id string) string { return filepath.Join(s.dir, id+".kdbx") }

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "0", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Server) revision(id string) (string, error) { return hashFile(s.file(id)) }
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func jsonOut(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) current(id, token string) bool {
	l, ok := s.leases[id]
	return ok && s.now().Before(l.expires) && len(token) == len(l.token) && subtle.ConstantTimeCompare([]byte(token), []byte(l.token)) == 1
}
func (s *Server) acquire(w http.ResponseWriter, r *http.Request, id string) {
	var input struct {
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil || len(input.Owner) > 128 {
		http.Error(w, "invalid request", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leases[id]; ok && s.now().Before(l.expires) {
		http.Error(w, "locked", http.StatusLocked)
		return
	}
	rev, err := s.revision(id)
	if err != nil {
		http.Error(w, "revision unavailable", 500)
		return
	}
	token, err := randToken()
	if err != nil {
		http.Error(w, "randomness unavailable", 500)
		return
	}
	exp := s.now().Add(leaseDuration)
	s.leases[id] = lease{token: token, owner: input.Owner, expires: exp}
	jsonOut(w, 200, LockResponse{Token: token, Expires: exp.UTC().Format(time.RFC3339Nano), Revision: rev})
}
func (s *Server) renew(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := r.Header.Get("X-KDBX-Lease")
	if !s.current(id, token) {
		http.Error(w, "lease lost", http.StatusConflict)
		return
	}
	l := s.leases[id]
	l.expires = s.now().Add(leaseDuration)
	s.leases[id] = l
	jsonOut(w, 200, map[string]string{"expires": l.expires.UTC().Format(time.RFC3339Nano)})
}
func (s *Server) release(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(id, r.Header.Get("X-KDBX-Lease")) {
		http.Error(w, "lease lost", http.StatusConflict)
		return
	}
	delete(s.leases, id)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) download(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A reader is allowed while someone edits; it receives the LAST committed blob.
	f, err := os.Open(s.file(id))
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "file unavailable", 500)
		return
	}
	defer f.Close()
	rev, err := s.revision(id)
	if err != nil {
		http.Error(w, "hash failed", 500)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", rev))
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (s *Server) publish(w http.ResponseWriter, r *http.Request, id string) {
	// Stage uploads before taking the state mutex. A slow client cannot starve reads.
	tmp, err := os.CreateTemp(s.dir, ".upload-*")
	if err != nil {
		http.Error(w, "storage unavailable", 500)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		http.Error(w, "storage unavailable", 500)
		return
	}
	n, copyErr := io.Copy(tmp, http.MaxBytesReader(w, r.Body, maxBody))
	if copyErr == nil && n == 0 {
		copyErr = errors.New("empty database")
	}
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		http.Error(w, "invalid upload", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(id, r.Header.Get("X-KDBX-Lease")) {
		http.Error(w, "lease lost", 409)
		return
	}
	rev, err := s.revision(id)
	if err != nil {
		http.Error(w, "revision unavailable", 500)
		return
	}
	// This is an optimistic revision guard IN ADDITION TO lock ownership.
	if r.Header.Get("If-Match") != "\""+rev+"\"" {
		http.Error(w, "stale revision", http.StatusPreconditionFailed)
		return
	}
	old := s.file(id)
	if rev != "0" {
		// Keep a unique historical snapshot of the previous encrypted revision.
		backup := filepath.Join(s.dir, id+"."+rev+".bak")
		if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
			src, err := os.Open(old)
			if err != nil {
				http.Error(w, "backup failed", 500)
				return
			}
			bf, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				src.Close()
				http.Error(w, "backup failed", 500)
				return
			}
			_, err = io.Copy(bf, src)
			src.Close()
			if err == nil {
				err = bf.Sync()
			}
			ce := bf.Close()
			if err == nil {
				err = ce
			}
			if err != nil {
				os.Remove(backup)
				http.Error(w, "backup failed", 500)
				return
			}
		} else if err != nil {
			http.Error(w, "backup failed", 500)
			return
		}
	}
	if err = os.Rename(tmpName, old); err != nil {
		http.Error(w, "publish failed", 500)
		return
	}
	// Directory sync makes the directory update durable on common POSIX filesystems.
	if err = syncDir(s.dir); err != nil {
		http.Error(w, "directory sync failed; check server state", 500)
		return
	}
	newRev, err := s.revision(id)
	if err != nil {
		http.Error(w, "revision unavailable", 500)
		return
	}
	w.Header().Set("ETag", "\""+newRev+"\"")
	jsonOut(w, 200, map[string]string{"revision": newRev})
}

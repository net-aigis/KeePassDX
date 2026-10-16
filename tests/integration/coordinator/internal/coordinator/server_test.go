package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const key = "this-is-a-long-strong-test-token-not-for-deployment"

func request(t *testing.T, s *Server, method, path, lease, rev string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+key)
	if lease != "" {
		r.Header.Set("X-KDBX-Lease", lease)
	}
	if rev != "" {
		r.Header.Set("If-Match", `"`+rev+`"`)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func lock(t *testing.T, s *Server) LockResponse {
	t.Helper()
	w := request(t, s, "POST", "/v1/databases/shared/lock", "", "", []byte(`{"owner":"alice"}`))
	if w.Code != 200 {
		t.Fatalf("lock: %d %s", w.Code, w.Body.String())
	}
	var result LockResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestExclusivePublication(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	a := lock(t, s)
	if a.Revision != "0" {
		t.Fatal(a)
	}
	if got := request(t, s, "POST", "/v1/databases/shared/lock", "", "", []byte(`{"owner":"bob"}`)).Code; got != 423 {
		t.Fatalf("second edit allowed: %d", got)
	}
	if got := request(t, s, "PUT", "/v1/databases/shared/file", "wrong", a.Revision, []byte("encrypted-A")).Code; got != 409 {
		t.Fatalf("unauthorized write %d", got)
	}
	w := request(t, s, "PUT", "/v1/databases/shared/file", a.Token, a.Revision, []byte("encrypted-A"))
	if w.Code != 200 {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	if got := request(t, s, "DELETE", "/v1/databases/shared/lock", a.Token, "", nil).Code; got != 204 {
		t.Fatalf("unlock: %d", got)
	}
	b := lock(t, s)
	if b.Revision == "0" {
		t.Fatal("revision didn't advance")
	}
	if got := request(t, s, "PUT", "/v1/databases/shared/file", b.Token, "0", []byte("stale")).Code; got != 412 {
		t.Fatalf("stale write succeeded: %d", got)
	}
	if got := request(t, s, "PUT", "/v1/databases/shared/file", a.Token, b.Revision, []byte("old lease")).Code; got != 409 {
		t.Fatalf("old lease succeeded: %d", got)
	}
	w = request(t, s, "GET", "/v1/databases/shared/file", "", "", nil)
	if w.Code != 200 || w.Body.String() != "encrypted-A" {
		t.Fatalf("read: %d %q", w.Code, w.Body.String())
	}
}
func TestExpirationFencing(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	a := lock(t, s)
	now = now.Add(2 * time.Minute)
	b := lock(t, s)
	if a.Token == b.Token {
		t.Fatal("reused token")
	}
	if got := request(t, s, "PUT", "/v1/databases/shared/file", a.Token, "0", []byte("stale")).Code; got != 409 {
		t.Fatalf("expired lease published %d", got)
	}
	if got := request(t, s, "PUT", "/v1/databases/shared/file", b.Token, "0", []byte("current")).Code; got != 200 {
		t.Fatalf("new lease failed %d", got)
	}
}
func TestParallelLock(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan int, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/v1/databases/db/lock", bytes.NewBufferString(`{"owner":"test"}`))
			r.Header.Set("Authorization", "Bearer "+key)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			results <- w.Code
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for result := range results {
		if result == 200 {
			success++
		} else if result != 423 {
			t.Fatalf("unexpected %d", result)
		}
	}
	if success != 1 {
		t.Fatalf("locks granted: %d", success)
	}
}
func TestAuthenticationAndTraversal(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1/databases/a/file", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	if got := request(t, s, "GET", "/v1/databases/../file", "", "", nil).Code; got != 404 {
		t.Fatalf("traversal accepted: %d", got)
	}
}

func TestBackupsAndVersionHistory(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	l := lock(t, s)
	first := []byte("encrypted-version-one")
	if got := request(t, s, "PUT", "/v1/databases/shared/file", l.Token, l.Revision, first).Code; got != 200 {
		t.Fatal(got)
	}
	if got := request(t, s, "DELETE", "/v1/databases/shared/lock", l.Token, "", nil).Code; got != 204 {
		t.Fatal(got)
	}
	l = lock(t, s)
	previous := l.Revision
	if got := request(t, s, "PUT", "/v1/databases/shared/file", l.Token, l.Revision, []byte("encrypted-version-two")).Code; got != 200 {
		t.Fatal(got)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "shared."+previous+".bak"))
	if err != nil || !bytes.Equal(stored, first) {
		t.Fatalf("backup missing/damaged: %v", err)
	}
}

func TestRenewLease(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	l := lock(t, s)
	now = now.Add(60 * time.Second)
	if got := request(t, s, "POST", "/v1/databases/shared/renew", l.Token, "", nil).Code; got != 200 {
		t.Fatalf("renew: %d", got)
	}
	now = now.Add(60 * time.Second)
	if got := request(t, s, "PUT", "/v1/databases/shared/file", l.Token, "0", []byte("after renewal")).Code; got != 200 {
		t.Fatalf("renewed lease not valid: %d", got)
	}
}

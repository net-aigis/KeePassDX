package coordinator

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestTwoConcurrentPublishesSameBase(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	l := lock(t, s)
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make(chan int, 2)
	for _, blob := range [][]byte{[]byte("ciphertext-A"), []byte("ciphertext-B")} {
		blob := blob
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := request(t, s, "PUT", "/v1/databases/shared/file", l.Token, l.Revision, blob)
			codes <- w.Code
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	ok, stale := 0, 0
	for c := range codes {
		if c == 200 {
			ok++
		} else if c == 412 {
			stale++
		} else {
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok != 1 || stale != 1 {
		t.Fatalf("one successful and one stale publication required: got %d/%d", ok, stale)
	}
	w := request(t, s, "GET", "/v1/databases/shared/file", "", "", nil)
	if w.Code != 200 || (w.Body.String() != "ciphertext-A" && w.Body.String() != "ciphertext-B") {
		t.Fatalf("unexpected committed contents: %d %s", w.Code, w.Body.String())
	}
}

type failsAfter struct{ n int }

func (r *failsAfter) Read(dst []byte) (int, error) {
	if r.n == 0 {
		r.n++
		return copy(dst, []byte("truncated encrypted KDBX")), nil
	}
	return 0, errors.New("network interrupted")
}
func TestInterruptedUploadMustNotPublish(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	l := lock(t, s)
	if w := request(t, s, "PUT", "/v1/databases/shared/file", l.Token, "0", []byte("previous complete encrypted database")); w.Code != 200 {
		t.Fatalf("initial put %d", w.Code)
	}
	old, err := s.revision("shared")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", "/v1/databases/shared/file", &failsAfter{})
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-KDBX-Lease", l.Token)
	req.Header.Set("If-Match", `"`+old+`"`)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code == 200 {
		t.Fatal("accepted interrupted upload")
	}
	got := request(t, s, "GET", "/v1/databases/shared/file", "", "", nil)
	if got.Code != 200 || got.Body.String() != "previous complete encrypted database" {
		t.Fatalf("committed value changed: %d %s", got.Code, got.Body.String())
	}
}

// Simulates lease expiration after upload data has arrived but before commit.
type advanceAfterRead struct {
	reader  io.Reader
	advance func()
}

func (a *advanceAfterRead) Read(p []byte) (int, error) {
	n, e := a.reader.Read(p)
	if n > 0 {
		a.advance()
	}
	return n, e
}
func TestLeaseExpiresWhileUploading(t *testing.T) {
	s, err := New(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	l := lock(t, s)
	body := &advanceAfterRead{reader: bytes.NewReader([]byte("encrypted-before-lease-expired")), advance: func() { now = now.Add(2 * time.Minute) }}
	req := httptest.NewRequest(http.MethodPut, "/v1/databases/shared/file", body)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-KDBX-Lease", l.Token)
	req.Header.Set("If-Match", `"0"`)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected lease loss after read, got %d: %s", w.Code, w.Body.String())
	}
	got := request(t, s, "GET", "/v1/databases/shared/file", "", "", nil)
	if got.Code != 404 {
		t.Fatalf("expired upload published: %d", got.Code)
	}
}

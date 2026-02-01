package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type mockPrompter struct {
	password   string
	err        error
	callCount  atomic.Int32
	onlyOnce   bool // If true, returns error on subsequent calls
	onceCalled atomic.Bool
	lastErrMsg string // Records the last error message passed to prompt
}

func (m *mockPrompter) PromptForPassword(errMsg string) (string, ResultNotifier, error) {
	m.callCount.Add(1)
	m.lastErrMsg = errMsg
	if m.onlyOnce {
		if m.onceCalled.Load() {
			return "", nil, errors.New("prompt called more than once")
		}
		m.onceCalled.Store(true)
	}

	return m.password, nil, m.err
}

type blockingPrompter struct {
	entered   chan struct{}
	passwordC chan string
	err       error
	callCount atomic.Int32
	once      atomic.Bool
}

func (p *blockingPrompter) PromptForPassword(errMsg string) (string, ResultNotifier, error) {
	p.callCount.Add(1)
	if p.once.Load() {
		return "", nil, errors.New("prompt called more than once")
	}
	p.once.Store(true)
	close(p.entered)
	password := <-p.passwordC
	return password, nil, p.err
}

// retryPrompter allows simulating password retries - returns different passwords on successive calls
type retryPrompter struct {
	passwords []string // Passwords to return on each call
	errs      []error  // Errors to return on each call (nil for success)
	callCount atomic.Int32
	errMsgs   []string // Records error messages passed on each call
	mu        sync.Mutex
}

func (p *retryPrompter) PromptForPassword(errMsg string) (string, ResultNotifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	idx := int(p.callCount.Add(1)) - 1
	p.errMsgs = append(p.errMsgs, errMsg)

	if idx >= len(p.passwords) {
		return "", nil, errors.New("no more passwords configured")
	}

	var err error
	if idx < len(p.errs) {
		err = p.errs[idx]
	}

	return p.passwords[idx], nil, err
}

// gatingErrCtx blocks on the first Err() call until allowed.
// This lets tests coordinate exactly when the pre-lock ctx.Err() checkpoint returns.
type gatingErrCtx struct {
	context.Context
	firstCalled      chan struct{}
	allowFirstReturn chan struct{}
	errCalls         atomic.Int32
}

func (c *gatingErrCtx) Err() error {
	if c.errCalls.Add(1) == 1 {
		close(c.firstCalled)
		<-c.allowFirstReturn
	}
	return c.Context.Err()
}

// blockingErrCtx blocks every Err() call until gate is closed.
// Useful to deterministically test that cancellation is checked at an explicit ctx.Err checkpoint.
type blockingErrCtx struct {
	context.Context
	called chan struct{}
	gate   chan struct{}
}

func (c *blockingErrCtx) Err() error {
	select {
	case <-c.called:
		// already signaled
	default:
		close(c.called)
	}
	<-c.gate
	return c.Context.Err()
}

// clientWithPrompter returns a test client with a mock prompter injected
func clientWithPrompter(ts *httptest.Server, prompter passwordPrompter, autoUnlock bool) *Client {
	c := &Client{
		baseURL:    ts.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		session:    &SessionManager{},
	}
	c.autoUnlock.Store(autoUnlock)
	c.prompter = prompter
	return c
}

// makeServeHealthy simulates a healthy serve process for testing
func makeServeHealthy(c *Client) {
	// Create a dummy "healthy" serve state
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serveCmd = &exec.Cmd{} // Non-nil indicates serve was started
	c.servePID = 12345       // Fake PID
	c.serveDone = make(chan error, 1)
	c.serveErr = nil
}

func TestEnsureUnlocked_AlreadyUnlocked(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Return unlocked status
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"unlocked"}}}`))
	}))
	defer ts.Close()

	prompter := &mockPrompter{}
	c := clientWithPrompter(ts, prompter, true)

	err := c.ensureUnlocked(context.Background())
	if err != nil {
		t.Fatalf("ensureUnlocked() error = %v, want nil", err)
	}

	// Verify IsLocked was called but prompter was not
	if callCount != 1 {
		t.Errorf("IsLocked called %d times, want 1", callCount)
	}
	if prompter.callCount.Load() != 0 {
		t.Errorf("Prompter called %d times, want 0", prompter.callCount.Load())
	}
}

func TestEnsureUnlocked_AutoUnlockDisabled_ReturnsErrVaultLocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return locked status
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
	}))
	defer ts.Close()

	prompter := &mockPrompter{}
	c := clientWithPrompter(ts, prompter, false) // autoUnlock disabled

	err := c.ensureUnlocked(context.Background())
	if !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("ensureUnlocked() error = %v, want ErrVaultLocked", err)
	}

	// Verify prompter was not called when autoUnlock is disabled
	if prompter.callCount.Load() != 0 {
		t.Errorf("Prompter called %d times, want 0", prompter.callCount.Load())
	}
}

func TestEnsureUnlocked_UnlocksSuccessfully(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var isLockedCalls, unlockCalls int
	var unlockBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			isLockedCalls++
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			unlockCalls++
			if r.Method != http.MethodPost {
				t.Fatalf("/unlock method = %s, want POST", r.Method)
			}
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read /unlock body: %v", err)
			}
			unlockBody = string(b)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	defer ts.Close()

	prompter := &mockPrompter{password: "test-password"}
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c) // Simulate healthy serve

	err := c.ensureUnlocked(context.Background())
	if err != nil {
		t.Fatalf("ensureUnlocked() error = %v, want nil", err)
	}

	// Verify IsLocked was called (first check)
	if isLockedCalls != 2 { // Once for quick check, once after lock
		t.Errorf("IsLocked called %d times, want 2", isLockedCalls)
	}
	// Verify prompter was called once
	if prompter.callCount.Load() != 1 {
		t.Errorf("Prompter called %d times, want 1", prompter.callCount.Load())
	}
	// Verify unlock was called
	if unlockCalls != 1 {
		t.Errorf("Unlock called %d times, want 1", unlockCalls)
	}
	if !strings.Contains(unlockBody, `"password":"test-password"`) {
		t.Fatalf("/unlock body %q missing password", unlockBody)
	}
	if got := c.session.GetSession(); got != "test-token" {
		t.Fatalf("session token = %q, want %q", got, "test-token")
	}
}

func TestEnsureUnlocked_UserCancellation(t *testing.T) {
	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unlock" {
			atomic.AddInt32(&unlockCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
	}))
	defer ts.Close()

	prompter := &mockPrompter{err: ErrUserCancelled}
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c) // Simulate healthy serve

	err := c.ensureUnlocked(context.Background())
	if !errors.Is(err, ErrUserCancelled) {
		t.Fatalf("ensureUnlocked() error = %v, want ErrUserCancelled", err)
	}
	if prompter.callCount.Load() != 1 {
		t.Fatalf("prompter calls = %d, want 1", prompter.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 0 {
		t.Fatalf("/unlock called %d times, want 0", unlockCalls)
	}
}

func TestEnsureUnlocked_ConcurrentCalls_OnlyOnePrompt(t *testing.T) {
	var isLockedCalls, unlockCalls int32
	var unlocked atomic.Bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			atomic.AddInt32(&isLockedCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			if unlocked.Load() {
				w.Write([]byte(`{"success":true,"data":{"template":{"status":"unlocked"}}}`))
			} else {
				w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
			}
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			unlocked.Store(true)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	defer ts.Close()

	// Use a prompter that returns successfully and counts calls
	prompter := &mockPrompter{
		password: "test-password",
		onlyOnce: true, // Will error if called more than once
	}

	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c) // Simulate healthy serve

	// Start multiple concurrent calls
	var wg sync.WaitGroup
	results := make([]error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = c.ensureUnlocked(context.Background())
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()

	// Verify all calls succeeded
	for i, err := range results {
		if err != nil {
			t.Errorf("Call %d failed: %v", i, err)
		}
	}

	// Verify only one prompt and one unlock (double-check locking should prevent multiple unlocks)
	if prompter.callCount.Load() != 1 {
		t.Errorf("Prompter called %d times, want 1", prompter.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 1 {
		t.Errorf("Unlock called %d times, want 1", unlockCalls)
	}
}

func TestEnsureUnlocked_ContextCancelled_BeforeLock(t *testing.T) {
	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unlock" {
			atomic.AddInt32(&unlockCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
	}))
	defer ts.Close()

	prompter := &mockPrompter{}
	c := clientWithPrompter(ts, prompter, true)

	base, cancel := context.WithCancel(context.Background())
	called := make(chan struct{})
	gate := make(chan struct{})
	ctx := &blockingErrCtx{Context: base, called: called, gate: gate}

	done := make(chan error, 1)
	go func() {
		done <- c.ensureUnlocked(ctx)
	}()

	// Wait until ensureUnlocked reaches the explicit ctx.Err() checkpoint.
	<-called
	// Cancel while ensureUnlocked is blocked inside Err().
	cancel()
	close(gate)

	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ensureUnlocked() error = %v, want context.Canceled", err)
	}

	// Verify prompter was not called
	if prompter.callCount.Load() != 0 {
		t.Errorf("Prompter called %d times, want 0", prompter.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 0 {
		t.Fatalf("/unlock called %d times, want 0", unlockCalls)
	}
}

func TestEnsureUnlocked_ContextCancelled_AfterLock(t *testing.T) {
	var statusCalls int32
	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			atomic.AddInt32(&statusCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	defer ts.Close()

	prompter := &mockPrompter{}
	c := clientWithPrompter(ts, prompter, true)

	// Force ensureUnlocked to block on unlockMu.Lock().
	c.unlockMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			c.unlockMu.Unlock()
		}
	})

	base, cancel := context.WithCancel(context.Background())
	ctx := &gatingErrCtx{
		Context:          base,
		firstCalled:      make(chan struct{}),
		allowFirstReturn: make(chan struct{}),
	}

	done := make(chan error, 1)
	go func() {
		done <- c.ensureUnlocked(ctx)
	}()

	// Wait for checkpoint A to be reached, then allow it to return nil.
	<-ctx.firstCalled
	close(ctx.allowFirstReturn)

	// Now cancel while the goroutine is blocked waiting for unlockMu.
	cancel()

	// Release unlockMu so the goroutine can acquire it and observe cancellation at checkpoint B.
	c.unlockMu.Unlock()
	locked = false
	err := <-done

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ensureUnlocked() error = %v, want context.Canceled", err)
	}
	if prompter.callCount.Load() != 0 {
		t.Fatalf("prompter calls = %d, want 0", prompter.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 0 {
		t.Fatalf("/unlock called %d times, want 0", unlockCalls)
	}
	// Only the quick IsLocked should have run; the post-lock re-check must not run because we exit at checkpoint B.
	if atomic.LoadInt32(&statusCalls) != 1 {
		t.Fatalf("/status calls = %d, want 1", statusCalls)
	}
}

func TestWithAutoUnlock_Success(t *testing.T) {
	var statusCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			atomic.AddInt32(&statusCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"unlocked"}}}`))
	}))
	defer ts.Close()

	prompter := &mockPrompter{}
	c := clientWithPrompter(ts, prompter, true)

	var called bool
	err := c.withAutoUnlock(context.Background(), func() error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("withAutoUnlock() error = %v", err)
	}
	if !called {
		t.Error("Inner function was not called")
	}
	if atomic.LoadInt32(&statusCalls) != 1 {
		t.Fatalf("/status calls = %d, want 1", statusCalls)
	}
	if prompter.callCount.Load() != 0 {
		t.Fatalf("prompter calls = %d, want 0", prompter.callCount.Load())
	}
}

func TestWithAutoUnlock_PropogatesError(t *testing.T) {
	var statusCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			atomic.AddInt32(&statusCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"unlocked"}}}`))
	}))
	defer ts.Close()

	prompter := &mockPrompter{}
	c := clientWithPrompter(ts, prompter, true)

	innerErr := errors.New("inner error")
	err := c.withAutoUnlock(context.Background(), func() error {
		return innerErr
	})

	if !errors.Is(err, innerErr) {
		t.Fatalf("withAutoUnlock() error = %v, want %v", err, innerErr)
	}
	if atomic.LoadInt32(&statusCalls) != 1 {
		t.Fatalf("/status calls = %d, want 1", statusCalls)
	}
}

func TestSetAutoUnlock_TogglesBehavior(t *testing.T) {
	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	defer ts.Close()

	prompter := &mockPrompter{password: "pw"}
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c) // Simulate healthy serve

	c.SetAutoUnlock(false)
	err := c.ensureUnlocked(context.Background())
	if !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("ensureUnlocked() error = %v, want ErrVaultLocked", err)
	}
	if prompter.callCount.Load() != 0 {
		t.Fatalf("prompter calls = %d, want 0", prompter.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 0 {
		t.Fatalf("/unlock calls = %d, want 0", unlockCalls)
	}

	c.SetAutoUnlock(true)
	err = c.ensureUnlocked(context.Background())
	if err != nil {
		t.Fatalf("ensureUnlocked() error = %v, want nil", err)
	}
	if prompter.callCount.Load() != 1 {
		t.Fatalf("prompter calls = %d, want 1", prompter.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 1 {
		t.Fatalf("/unlock calls = %d, want 1", unlockCalls)
	}
}

func TestWithAutoUnlock_DoesNotCallFnOnEnsureError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
	}))
	defer ts.Close()

	c := clientWithPrompter(ts, &mockPrompter{}, false)
	var called bool
	err := c.withAutoUnlock(context.Background(), func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("withAutoUnlock() error = %v, want ErrVaultLocked", err)
	}
	if called {
		t.Fatal("fn was called, want not called")
	}
}

func TestEnsureUnlocked_RecheckAfterLockAvoidsPrompt(t *testing.T) {
	var unlockCalls int32
	var statusCalls int32
	var unlocked atomic.Bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			atomic.AddInt32(&statusCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			if unlocked.Load() {
				w.Write([]byte(`{"success":true,"data":{"template":{"status":"unlocked"}}}`))
			} else {
				w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
			}
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			unlocked.Store(true)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	defer ts.Close()

	block := &blockingPrompter{
		entered:   make(chan struct{}),
		passwordC: make(chan string, 1),
	}

	c := clientWithPrompter(ts, block, true)
	makeServeHealthy(c) // Simulate healthy serve

	// Goroutine A will enter the prompt while holding unlockMu.
	aDone := make(chan error, 1)
	go func() { aDone <- c.ensureUnlocked(context.Background()) }()
	<-block.entered

	// Goroutine B starts while A holds the lock.
	bDone := make(chan error, 1)
	go func() { bDone <- c.ensureUnlocked(context.Background()) }()

	// Allow A to unlock.
	block.passwordC <- "pw"
	if err := <-aDone; err != nil {
		t.Fatalf("A ensureUnlocked error = %v", err)
	}

	if err := <-bDone; err != nil {
		t.Fatalf("B ensureUnlocked error = %v", err)
	}

	// B should not prompt or unlock.
	if block.callCount.Load() != 1 {
		t.Fatalf("prompter calls = %d, want 1", block.callCount.Load())
	}
	if atomic.LoadInt32(&unlockCalls) != 1 {
		t.Fatalf("/unlock calls = %d, want 1", unlockCalls)
	}
	if atomic.LoadInt32(&statusCalls) < 2 {
		t.Fatalf("/status calls = %d, want >=2", statusCalls)
	}
}

// --- Error Sanitization Tests ---

func TestAPIError_Error_NeverLeaksBody(t *testing.T) {
	apiErr := &APIError{
		StatusCode: 401,
		Path:       "/unlock",
		debugBody:  `{"error":"invalid password","password":"secret123"}`,
	}

	errMsg := apiErr.Error()

	// Verify error message is safe
	if errMsg != "API error 401 on /unlock" {
		t.Errorf("Error() = %q, want %q", errMsg, "API error 401 on /unlock")
	}

	// Verify body is NOT in error message
	if strings.Contains(errMsg, "secret123") {
		t.Error("Error() leaked sensitive data from body")
	}
	if strings.Contains(errMsg, "password") {
		t.Error("Error() leaked password field name")
	}
}

func TestAPIError_DebugDetails_ReturnsBody(t *testing.T) {
	body := `{"error":"test error"}`
	apiErr := &APIError{
		StatusCode: 400,
		Path:       "/test",
		debugBody:  body,
	}

	details := apiErr.DebugDetails()
	if details != body {
		t.Errorf("DebugDetails() = %q, want %q", details, body)
	}
}

func TestLogHTTPBodySnippet_TruncatesLongBody(t *testing.T) {
	// Create a body longer than 512 bytes
	longBody := strings.Repeat("x", 600)

	snippet := logHTTPBodySnippet("test", longBody)

	// Should be truncated and capped at 512 bytes
	if len(snippet) > 512 {
		t.Errorf("logHTTPBodySnippet length = %d, want <= 512", len(snippet))
	}

	// Should contain truncation indicator
	if !strings.Contains(snippet, "[truncated") {
		t.Error("logHTTPBodySnippet missing [truncated indicator")
	}
}

func TestLogHTTPBodySnippet_RedactsPassword(t *testing.T) {
	body := `{"password":"secret123","username":"user"}`

	snippet := logHTTPBodySnippet("test", body)

	// Should redact password value
	if strings.Contains(snippet, "secret123") {
		t.Error("logHTTPBodySnippet failed to redact password")
	}

	// Should keep username
	if !strings.Contains(snippet, "username") {
		t.Error("logHTTPBodySnippet over-redacted username field")
	}
}

func TestLogHTTPBodySnippet_RedactsToken(t *testing.T) {
	body := `{"token":"abc123def456","data":"public"}`

	snippet := logHTTPBodySnippet("test", body)

	if strings.Contains(snippet, "abc123") {
		t.Error("logHTTPBodySnippet failed to redact token")
	}

	if !strings.Contains(snippet, "data") {
		t.Error("logHTTPBodySnippet over-redacted data field")
	}
}

func TestLogHTTPBodySnippet_RedactsSession(t *testing.T) {
	body := `{"session":"sessionkey123","public":"value"}`

	snippet := logHTTPBodySnippet("test", body)

	if strings.Contains(snippet, "sessionkey123") {
		t.Error("logHTTPBodySnippet failed to redact session")
	}
}

func TestLogHTTPBodySnippet_RedactsAuthorization(t *testing.T) {
	body := `{"authorization":"Bearer token123","action":"list"}`

	snippet := logHTTPBodySnippet("test", body)

	if strings.Contains(snippet, "token123") {
		t.Error("logHTTPBodySnippet failed to redact authorization")
	}
}

func TestLogHTTPBodySnippet_RedactsRaw(t *testing.T) {
	body := `{"raw":"sensitive_raw_data","name":"test"}`

	snippet := logHTTPBodySnippet("test", body)

	if strings.Contains(snippet, "sensitive_raw_data") {
		t.Error("logHTTPBodySnippet failed to redact raw")
	}
}

func TestLogHTTPBodySnippet_RedactsKey(t *testing.T) {
	body := `{"key":"secret_key_123","id":"public_id"}`

	snippet := logHTTPBodySnippet("test", body)

	if strings.Contains(snippet, "secret_key") {
		t.Error("logHTTPBodySnippet failed to redact key")
	}
}

func TestLogHTTPBodySnippet_ShortBodyNotTruncated(t *testing.T) {
	body := "short body"

	snippet := logHTTPBodySnippet("test", body)

	if strings.Contains(snippet, "[truncated") {
		t.Error("logHTTPBodySnippet truncated short body")
	}

	if !strings.Contains(snippet, body) {
		t.Error("logHTTPBodySnippet didn't preserve short body")
	}
}

func TestSetDebug_ControlsLogging(t *testing.T) {
	c := NewClient(8087)

	// Initially debug should be false
	if c.debug.Load() {
		t.Error("debug should be false initially")
	}

	// Set to true
	c.SetDebug(true)
	if !c.debug.Load() {
		t.Error("debug should be true after SetDebug(true)")
	}

	// Set to false
	c.SetDebug(false)
	if c.debug.Load() {
		t.Error("debug should be false after SetDebug(false)")
	}
}

// --- Process Lifecycle Tests (M3) ---

func TestServeHealthy_NeverStarted(t *testing.T) {
	c := NewClient(8087)

	err := c.ServeHealthy()
	if err == nil {
		t.Fatal("ServeHealthy() should return error when serve never started")
	}
	if !strings.Contains(err.Error(), "not started") && !strings.Contains(err.Error(), "never started") {
		t.Errorf("ServeHealthy() error = %v, want error about not started", err)
	}
}

func TestServeHealthy_ProcessExited(t *testing.T) {
	c := NewClient(8087)

	// Simulate a process that started but then exited
	c.mu.Lock()
	c.serveDone = make(chan error, 1)
	c.serveErr = errors.New("process exited")
	c.serveCmd = nil // Process is gone
	c.servePID = 0
	c.mu.Unlock()

	err := c.ServeHealthy()
	if err == nil {
		t.Fatal("ServeHealthy() should return error when process exited")
	}
	if !strings.Contains(err.Error(), "exited") {
		t.Errorf("ServeHealthy() error = %v, want error about process exited", err)
	}
}

func TestEnsureUnlocked_RequiresHealthyServe(t *testing.T) {
	// Create a server that returns "locked" status
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
	}))
	defer ts.Close()

	c := clientWithPrompter(ts, &mockPrompter{password: "test"}, true)

	// ServeHealthy should fail because serve never started
	// This will fail when it tries to prompt for password
	err := c.ensureUnlocked(context.Background())
	if err == nil {
		t.Fatal("ensureUnlocked() should fail when serve not healthy")
	}
	if !strings.Contains(err.Error(), "not healthy") && !strings.Contains(err.Error(), "not started") {
		t.Errorf("ensureUnlocked() error = %v, want error about backend health", err)
	}
}

func TestStop_SendsSIGTERM_ThenSIGKILL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	// This test verifies Stop sends SIGTERM, waits, then SIGKILL if needed
	// We'll use a real process that ignores SIGTERM
	ctx := context.Background()
	c := NewClient(8087)

	// Start a process that ignores SIGTERM (sleep ignores it on some systems)
	// We'll use a shell script that traps TERM
	cmd := exec.CommandContext(ctx, "sh", "-c", "trap '' TERM; sleep 100")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start test process: %v", err)
	}

	c.mu.Lock()
	c.serveCmd = cmd
	c.servePID = cmd.Process.Pid
	c.serveDone = make(chan error, 1)
	c.mu.Unlock()

	// Spawn goroutine to wait for process
	go func() {
		err := cmd.Wait()
		c.serveDone <- err
	}()

	// Give process time to start
	time.Sleep(100 * time.Millisecond)

	// Stop should send SIGTERM, wait 3s, then SIGKILL
	start := time.Now()
	err := c.Stop()
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Should take at least 3 seconds (SIGTERM timeout) but less than 5
	if elapsed < 3*time.Second {
		t.Errorf("Stop() took %v, expected >= 3s (SIGTERM timeout)", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Stop() took %v, expected < 5s (should SIGKILL after 3s)", elapsed)
	}

	// Process should be dead
	if cmd.Process != nil {
		if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
			t.Error("Process still alive after Stop()")
		}
	}
}

func TestStop_ReapsZombie(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	ctx := context.Background()
	c := NewClient(8087)

	// Start a process that exits immediately
	cmd := exec.CommandContext(ctx, "true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start test process: %v", err)
	}

	c.mu.Lock()
	c.serveCmd = cmd
	c.servePID = cmd.Process.Pid
	c.serveDone = make(chan error, 1)
	c.mu.Unlock()

	// Spawn goroutine to wait
	go func() {
		err := cmd.Wait()
		c.serveDone <- err
	}()

	// Wait for process to exit
	time.Sleep(100 * time.Millisecond)

	// Stop should reap the zombie
	err := c.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Verify serveDone was consumed (reaped)
	select {
	case <-c.serveDone:
		t.Error("serveDone should be consumed after Stop()")
	default:
		// Good - channel should be drained
	}
}

func TestStartServe_FailClosed_StopsOnReadinessFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	_ = NewClient(9999) // Use a port we control

	// Start a fake bw serve that exits immediately (simulate failure)
	// We can't easily test this without mocking exec.Command
	// For now, this test documents the expected behavior
	t.Skip("TODO: implement with exec.Command mocking or integration test")
}

func TestStartServe_CancelContextAfterReady_DoesNotStopServe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	// Install a `bw` shim in PATH that implements `bw serve`.
	shimDir := t.TempDir()
	bwPath := filepath.Join(shimDir, "bw")
	shim := `#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" != "serve" ]; then
  echo "unsupported command: ${1:-}" 1>&2
  exit 2
fi

host="127.0.0.1"
port=""
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    --hostname)
      host="$2"; shift 2 ;;
    --port)
      port="$2"; shift 2 ;;
    *)
      shift ;;
  esac
done

if [ -z "$port" ]; then
  echo "missing --port" 1>&2
  exit 2
fi

export BW_SHIM_PORT="$port"

exec python3 - <<'PY'
import http.server
import json
import socketserver

HOST = "127.0.0.1"
PORT = int(__import__("os").environ["BW_SHIM_PORT"])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/status":
            body = json.dumps({"success": True, "data": {"template": {"status": "locked"}}}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Silence test output
        return

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
    httpd.serve_forever()
PY
`

	if err := os.WriteFile(bwPath, []byte(shim), 0o755); err != nil {
		t.Fatalf("write bw shim: %v", err)
	}

	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Pick a port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	// Start serve with a startup timeout context, then cancel it after readiness.
	c := NewClient(port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pass chosen port to the shim via env.
	c.mu.Lock()
	// StartServe uses os.Environ when starting the process. We can't directly set Cmd.Env here,
	// so we use an env var that the shim reads.
	c.mu.Unlock()
	t.Setenv("BW_SHIM_PORT", fmt.Sprintf("%d", port))

	if err := c.StartServe(ctx, port); err != nil {
		t.Fatalf("StartServe() error = %v", err)
	}

	// Canceling ctx after readiness should not stop the serve process.
	cancel()
	time.Sleep(200 * time.Millisecond)

	if err := c.ServeHealthy(); err != nil {
		t.Fatalf("ServeHealthy() after ctx cancel error = %v", err)
	}

	if _, err := c.Status(context.Background()); err != nil {
		t.Fatalf("Status() after ctx cancel error = %v", err)
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

// --- Password Retry Tests ---

func TestEnsureUnlocked_RetryOnWrongPassword_SuccessOnSecondAttempt(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var unlockCalls int32
	var lastPassword string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			b, _ := io.ReadAll(r.Body)
			lastPassword = string(b)
			w.Header().Set("Content-Type", "application/json")
			// First call returns invalid password, second returns success
			if atomic.LoadInt32(&unlockCalls) == 1 {
				w.Write([]byte(`{"success":false,"data":{"message":"Invalid master password"}}`))
			} else {
				w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
			}
		}
	}))
	defer ts.Close()

	prompter := &retryPrompter{
		passwords: []string{"wrong-password", "correct-password"},
	}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)

	err := c.ensureUnlocked(context.Background())
	if err != nil {
		t.Fatalf("ensureUnlocked() error = %v, want nil", err)
	}

	// Verify we made 2 unlock attempts
	if got := atomic.LoadInt32(&unlockCalls); got != 2 {
		t.Errorf("unlock calls = %d, want 2", got)
	}

	// Verify prompter was called twice
	if got := prompter.callCount.Load(); got != 2 {
		t.Errorf("prompter calls = %d, want 2", got)
	}

	// Verify first prompt had no error message, second had retry message
	if prompter.errMsgs[0] != "" {
		t.Errorf("first prompt errMsg = %q, want empty", prompter.errMsgs[0])
	}
	if !strings.Contains(prompter.errMsgs[1], "Incorrect password") {
		t.Errorf("second prompt errMsg = %q, want to contain 'Incorrect password'", prompter.errMsgs[1])
	}
	if !strings.Contains(prompter.errMsgs[1], "2 attempt(s) remaining") {
		t.Errorf("second prompt errMsg = %q, want to contain '2 attempt(s) remaining'", prompter.errMsgs[1])
	}

	// Verify final password was correct
	if !strings.Contains(lastPassword, "correct-password") {
		t.Errorf("last password = %q, want to contain 'correct-password'", lastPassword)
	}
}

func TestEnsureUnlocked_RetryExhausted_ReturnsMaxRetriesError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			// Always return invalid password
			w.Write([]byte(`{"success":false,"data":{"message":"Invalid master password"}}`))
		}
	}))
	defer ts.Close()

	prompter := &retryPrompter{
		passwords: []string{"wrong1", "wrong2", "wrong3"},
	}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)

	err := c.ensureUnlocked(context.Background())
	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Fatalf("ensureUnlocked() error = %v, want ErrMaxRetriesExceeded", err)
	}

	// Verify we made exactly 3 unlock attempts
	if got := atomic.LoadInt32(&unlockCalls); got != 3 {
		t.Errorf("unlock calls = %d, want 3", got)
	}

	// Verify prompter was called 3 times
	if got := prompter.callCount.Load(); got != 3 {
		t.Errorf("prompter calls = %d, want 3", got)
	}

	// Verify error messages on retries
	if prompter.errMsgs[0] != "" {
		t.Errorf("first prompt errMsg = %q, want empty", prompter.errMsgs[0])
	}
	if !strings.Contains(prompter.errMsgs[1], "2 attempt(s) remaining") {
		t.Errorf("second prompt errMsg = %q, want '2 attempt(s) remaining'", prompter.errMsgs[1])
	}
	if !strings.Contains(prompter.errMsgs[2], "1 attempt(s) remaining") {
		t.Errorf("third prompt errMsg = %q, want '1 attempt(s) remaining'", prompter.errMsgs[2])
	}
}

func TestEnsureUnlocked_UserCancellationDuringRetry_StopsImmediately(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"data":{"message":"Invalid master password"}}`))
		}
	}))
	defer ts.Close()

	// Cancel on second prompt
	prompter := &retryPrompter{
		passwords: []string{"wrong1", ""},
		errs:      []error{nil, ErrUserCancelled},
	}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)

	err := c.ensureUnlocked(context.Background())
	if !errors.Is(err, ErrUserCancelled) {
		t.Fatalf("ensureUnlocked() error = %v, want ErrUserCancelled", err)
	}

	// Verify we only made 1 unlock attempt (before cancellation)
	if got := atomic.LoadInt32(&unlockCalls); got != 1 {
		t.Errorf("unlock calls = %d, want 1", got)
	}

	// Verify prompter was called twice (first prompt + cancel on second)
	if got := prompter.callCount.Load(); got != 2 {
		t.Errorf("prompter calls = %d, want 2", got)
	}
}

func TestEnsureUnlocked_NonPasswordError_DoesNotRetry(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			// Return a non-password error (network error, API error, etc.)
			w.Write([]byte(`{"success":false,"data":{"message":"Connection to server failed"}}`))
		}
	}))
	defer ts.Close()

	prompter := &retryPrompter{
		passwords: []string{"password1", "password2", "password3"},
	}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)

	err := c.ensureUnlocked(context.Background())
	if err == nil {
		t.Fatal("ensureUnlocked() should fail on non-password error")
	}
	if errors.Is(err, ErrMaxRetriesExceeded) {
		t.Fatal("ensureUnlocked() should not return ErrMaxRetriesExceeded for non-password errors")
	}

	// Verify we only made 1 unlock attempt (no retry for non-password errors)
	if got := atomic.LoadInt32(&unlockCalls); got != 1 {
		t.Errorf("unlock calls = %d, want 1", got)
	}

	// Verify prompter was only called once
	if got := prompter.callCount.Load(); got != 1 {
		t.Errorf("prompter calls = %d, want 1", got)
	}
}

func TestEnsureUnlocked_SuccessOnFirstAttempt_NoRetryNeeded(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	defer ts.Close()

	prompter := &retryPrompter{
		passwords: []string{"correct-password"},
	}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)

	err := c.ensureUnlocked(context.Background())
	if err != nil {
		t.Fatalf("ensureUnlocked() error = %v, want nil", err)
	}

	// Verify we made exactly 1 unlock attempt
	if got := atomic.LoadInt32(&unlockCalls); got != 1 {
		t.Errorf("unlock calls = %d, want 1", got)
	}

	// Verify prompter was called once with no error message
	if got := prompter.callCount.Load(); got != 1 {
		t.Errorf("prompter calls = %d, want 1", got)
	}
	if prompter.errMsgs[0] != "" {
		t.Errorf("first prompt errMsg = %q, want empty", prompter.errMsgs[0])
	}
}

func TestEnsureUnlocked_ContextCancelledDuringRetryLoop(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	var unlockCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			atomic.AddInt32(&unlockCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"data":{"message":"Invalid master password"}}`))
		}
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Prompter that cancels context on second call
	prompter := &retryPrompter{
		passwords: []string{"wrong1", "wrong2"},
	}

	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)

	// Start ensureUnlocked in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- c.ensureUnlocked(ctx)
	}()

	// Wait a bit then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-done
	// Could be context.Canceled or invalid password depending on timing
	// The key is that it doesn't hang
	if err == nil {
		t.Fatal("ensureUnlocked() should fail when context is cancelled")
	}
}

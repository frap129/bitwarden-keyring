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

func (m *mockPrompter) PromptForPassword(_ context.Context, errMsg string) (string, ResultNotifier, error) {
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

func (p *blockingPrompter) PromptForPassword(_ context.Context, errMsg string) (string, ResultNotifier, error) {
	p.callCount.Add(1)
	if p.once.Load() {
		return "", nil, errors.New("prompt called more than once")
	}
	p.once.Store(true)
	close(p.entered)
	password := <-p.passwordC
	return password, nil, p.err
}

type flightPromptResult struct {
	password string
	err      error
}

type flightPrompter struct {
	entered   chan struct{}
	release   chan struct{}
	sequence  []flightPromptResult
	callCount atomic.Int32
	enterOnce sync.Once
	relOnce   sync.Once
}

type panicPrompter struct {
	entered   chan struct{}
	release   chan struct{}
	panicWith any
	callCount atomic.Int32
}

func (p *panicPrompter) PromptForPassword(context.Context, string) (string, ResultNotifier, error) {
	p.callCount.Add(1)
	close(p.entered)
	<-p.release
	panic(p.panicWith)
}

func (p *flightPrompter) PromptForPassword(context.Context, string) (string, ResultNotifier, error) {
	index := int(p.callCount.Add(1)) - 1
	p.enterOnce.Do(func() { close(p.entered) })
	<-p.release
	if index >= len(p.sequence) {
		return "", nil, errors.New("no more flight prompt results configured")
	}
	result := p.sequence[index]
	return result.password, nil, result.err
}

func (p *flightPrompter) releasePrompt() {
	p.relOnce.Do(func() { close(p.release) })
}

type startBarrier struct {
	want     int32
	arrived  chan struct{}
	release  chan struct{}
	count    atomic.Int32
	closeOne sync.Once
	relOnce  sync.Once
}

func (b *startBarrier) releaseStart() {
	b.relOnce.Do(func() { close(b.release) })
}

type testSignal struct {
	channel chan struct{}
	once    sync.Once
}

func newTestSignal() *testSignal {
	return &testSignal{channel: make(chan struct{})}
}

func (s *testSignal) trigger() {
	s.once.Do(func() { close(s.channel) })
}

func newStartBarrier(want int) *startBarrier {
	return &startBarrier{
		want:    int32(want),
		arrived: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *startBarrier) handleStatus(w http.ResponseWriter, r *http.Request) {
	count := b.count.Add(1)
	if count <= b.want {
		if count == b.want {
			b.closeOne.Do(func() { close(b.arrived) })
		}
		select {
		case <-b.release:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func waitForTestSignal(t *testing.T, ctx context.Context, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", name, ctx.Err())
	}
}

func releaseConcurrentStart(t *testing.T, ctx context.Context, barrier *startBarrier) {
	t.Helper()
	waitForTestSignal(t, ctx, barrier.arrived, "initial locked status checks")
	if got := barrier.count.Load(); got != barrier.want {
		t.Fatalf("initial /status calls before release = %d, want %d", got, barrier.want)
	}
	barrier.releaseStart()
}

func waitForEnsureResults(t *testing.T, ctx context.Context, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	waitForTestSignal(t, ctx, done, "ensureUnlocked callers")
}

func waitForTestError(t *testing.T, ctx context.Context, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", name, ctx.Err())
		return ctx.Err()
	}
}

// retryPrompter allows simulating password retries - returns different passwords on successive calls
type retryPrompter struct {
	passwords []string // Passwords to return on each call
	errs      []error  // Errors to return on each call (nil for success)
	callCount atomic.Int32
	errMsgs   []string // Records error messages passed on each call
	mu        sync.Mutex
}

type notifierRetryPrompter struct {
	retryNotified chan struct{}
	releaseRetry  chan struct{}
	callCount     atomic.Int32
	retryCount    atomic.Int32
}

func (p *notifierRetryPrompter) PromptForPassword(_ context.Context, _ string) (string, ResultNotifier, error) {
	if p.callCount.Add(1) == 1 {
		return "wrong-password", func(success bool, _ string, allowRetry bool) {
			if !success && allowRetry && p.retryCount.Add(1) == 1 {
				close(p.retryNotified)
			}
		}, nil
	}
	<-p.releaseRetry
	return "correct-password", func(bool, string, bool) {}, nil
}

func (p *retryPrompter) PromptForPassword(_ context.Context, errMsg string) (string, ResultNotifier, error) {
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

func TestEnsureUnlocked_ConcurrentCalls_UserCancellationSharesResult(t *testing.T) {
	const callers = 5
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	barrier := newStartBarrier(callers)
	var unlockCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			barrier.handleStatus(w, r)
		case "/unlock":
			unlockCalls.Add(1)
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(barrier.releaseStart)

	prompter := &flightPrompter{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		sequence: []flightPromptResult{{err: ErrUserCancelled}},
	}
	t.Cleanup(prompter.releasePrompt)
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c)
	joined := newTestSignal()
	var joiners atomic.Int32
	c.flightWaiterHook = func(*unlockFlight) {
		if joiners.Add(1) == callers-1 {
			joined.trigger()
		}
	}

	results := make([]error, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = c.ensureUnlocked(ctx)
		}(i)
	}
	releaseConcurrentStart(t, ctx, barrier)
	waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
	waitForTestSignal(t, ctx, joined.channel, "four flight joiners")
	prompter.releasePrompt()
	waitForEnsureResults(t, ctx, &wg)

	for i, err := range results {
		if !errors.Is(err, ErrUserCancelled) {
			t.Errorf("caller %d error = %v, want ErrUserCancelled", i, err)
		}
	}
	if got := joiners.Load(); got != callers-1 {
		t.Errorf("flight joiners = %d, want %d", got, callers-1)
	}
	if got := prompter.callCount.Load(); got != 1 {
		t.Errorf("prompter calls = %d, want 1", got)
	}
	if got := unlockCalls.Load(); got != 0 {
		t.Errorf("unlock calls = %d, want 0", got)
	}
}

func TestEnsureUnlocked_ConcurrentCalls_MaxRetriesSharesResult(t *testing.T) {
	const callers = 5
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	maxRetries := DefaultSessionConfig().MaxPasswordRetries

	barrier := newStartBarrier(callers)
	var unlockCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			barrier.handleStatus(w, r)
		case "/unlock":
			unlockCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(barrier.releaseStart)

	sequence := make([]flightPromptResult, maxRetries)
	for i := range sequence {
		sequence[i].password = "wrong"
	}
	prompter := &flightPrompter{entered: make(chan struct{}), release: make(chan struct{}), sequence: sequence}
	t.Cleanup(prompter.releasePrompt)
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = maxRetries
	makeServeHealthy(c)
	joined := newTestSignal()
	var joiners atomic.Int32
	c.flightWaiterHook = func(*unlockFlight) {
		if joiners.Add(1) == callers-1 {
			joined.trigger()
		}
	}

	results := make([]error, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = c.ensureUnlocked(ctx)
		}(i)
	}
	releaseConcurrentStart(t, ctx, barrier)
	waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
	waitForTestSignal(t, ctx, joined.channel, "four flight joiners")
	prompter.releasePrompt()
	waitForEnsureResults(t, ctx, &wg)

	for i, err := range results {
		if !errors.Is(err, ErrMaxRetriesExceeded) {
			t.Errorf("caller %d error = %v, want ErrMaxRetriesExceeded", i, err)
		}
	}
	if got := prompter.callCount.Load(); got != int32(maxRetries) {
		t.Errorf("prompter calls = %d, want %d", got, maxRetries)
	}
	if got := unlockCalls.Load(); got != int32(maxRetries) {
		t.Errorf("unlock calls = %d, want %d", got, maxRetries)
	}
}

func TestEnsureUnlocked_ConcurrentCalls_NonPasswordFailureSharesResult(t *testing.T) {
	const callers = 5
	errConcurrentUnlock := errors.New("concurrent unlock failure")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	barrier := newStartBarrier(callers)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		barrier.handleStatus(w, r)
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(barrier.releaseStart)

	prompter := &flightPrompter{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		sequence: []flightPromptResult{{password: "wrong"}},
	}
	t.Cleanup(prompter.releasePrompt)
	c := clientWithPrompter(ts, prompter, true)
	transport := http.DefaultTransport
	var unlockCalls atomic.Int32
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/unlock" {
			unlockCalls.Add(1)
			return nil, errConcurrentUnlock
		}
		return transport.RoundTrip(r)
	})
	makeServeHealthy(c)
	joined := newTestSignal()
	var joiners atomic.Int32
	c.flightWaiterHook = func(*unlockFlight) {
		if joiners.Add(1) == callers-1 {
			joined.trigger()
		}
	}

	results := make([]error, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = c.ensureUnlocked(ctx)
		}(i)
	}
	releaseConcurrentStart(t, ctx, barrier)
	waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
	waitForTestSignal(t, ctx, joined.channel, "four flight joiners")
	prompter.releasePrompt()
	waitForEnsureResults(t, ctx, &wg)

	for i, err := range results {
		if !errors.Is(err, errConcurrentUnlock) {
			t.Errorf("caller %d error = %v, want errConcurrentUnlock", i, err)
		}
	}
	if got := prompter.callCount.Load(); got != 1 {
		t.Errorf("prompter calls = %d, want 1", got)
	}
	if got := unlockCalls.Load(); got != 1 {
		t.Errorf("unlock calls = %d, want 1", got)
	}
}

func TestEnsureUnlocked_OwnerPanicPublishesAbortToWaiters(t *testing.T) {
	const callers = 5
	panicValue := errors.New("prompter panic")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	barrier := newStartBarrier(callers)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		barrier.handleStatus(w, r)
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(barrier.releaseStart)

	prompter := &panicPrompter{
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
		panicWith: panicValue,
	}
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c)
	joined := newTestSignal()
	var joiners atomic.Int32
	c.flightWaiterHook = func(*unlockFlight) {
		if joiners.Add(1) == callers-1 {
			joined.trigger()
		}
	}

	results := make([]error, callers)
	panics := make([]any, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			defer func() { panics[index] = recover() }()
			results[index] = c.ensureUnlocked(ctx)
		}(i)
	}
	releaseConcurrentStart(t, ctx, barrier)
	waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
	waitForTestSignal(t, ctx, joined.channel, "panic-flight waiters")
	close(prompter.release)
	waitForEnsureResults(t, ctx, &wg)

	panicCount := 0
	for i := range results {
		if panics[i] != nil {
			panicCount++
			if panics[i] != panicValue {
				t.Errorf("caller %d recovered panic = %v, want %v", i, panics[i], panicValue)
			}
			continue
		}
		if !errors.Is(results[i], errUnlockFlightAborted) {
			t.Errorf("waiter %d error = %v, want errUnlockFlightAborted", i, results[i])
		}
	}
	if panicCount != 1 {
		t.Errorf("recovered panics = %d, want 1", panicCount)
	}
	if got := prompter.callCount.Load(); got != 1 {
		t.Errorf("prompter calls = %d, want 1", got)
	}
}

func TestEnsureUnlocked_ConcurrentWaiterContextCancellationWins(t *testing.T) {
	t.Run("cancellation while owner remains blocked", func(t *testing.T) {
		ctx, cancelOuter := context.WithTimeout(context.Background(), time.Second)
		defer cancelOuter()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		}))
		t.Cleanup(ts.Close)

		prompter := &flightPrompter{entered: make(chan struct{}), release: make(chan struct{}), sequence: []flightPromptResult{{err: ErrUserCancelled}}}
		t.Cleanup(prompter.releasePrompt)
		c := clientWithPrompter(ts, prompter, true)
		makeServeHealthy(c)
		joined := newTestSignal()
		c.flightWaiterHook = func(*unlockFlight) { joined.trigger() }

		ownerDone := make(chan error, 1)
		go func() { ownerDone <- c.ensureUnlocked(ctx) }()
		waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
		waiterCtx, cancelWaiter := context.WithCancel(ctx)
		t.Cleanup(cancelWaiter)
		waiterDone := make(chan error, 1)
		go func() { waiterDone <- c.ensureUnlocked(waiterCtx) }()
		waitForTestSignal(t, ctx, joined.channel, "waiter join")
		cancelWaiter()
		select {
		case err := <-waiterDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("waiter error = %v, want context.Canceled", err)
			}
		case <-prompter.release:
			t.Fatal("owner prompt unexpectedly released")
		case <-ctx.Done():
			t.Fatalf("waiter did not honor cancellation: %v", ctx.Err())
		}
		prompter.releasePrompt()
		if err := waitForTestError(t, ctx, ownerDone, "owner result"); !errors.Is(err, ErrUserCancelled) {
			t.Fatalf("owner error = %v, want ErrUserCancelled", err)
		}
	})

	t.Run("context wins when context and flight are both done", func(t *testing.T) {
		ctx, cancelOuter := context.WithTimeout(context.Background(), time.Second)
		defer cancelOuter()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		}))
		t.Cleanup(ts.Close)

		prompter := &flightPrompter{entered: make(chan struct{}), release: make(chan struct{}), sequence: []flightPromptResult{{err: ErrUserCancelled}}}
		t.Cleanup(prompter.releasePrompt)
		c := clientWithPrompter(ts, prompter, true)
		makeServeHealthy(c)
		hookEntered := newTestSignal()
		hookRelease := newTestSignal()
		t.Cleanup(hookRelease.trigger)
		c.flightWaiterHook = func(*unlockFlight) {
			hookEntered.trigger()
			<-hookRelease.channel
		}

		ownerDone := make(chan error, 1)
		go func() { ownerDone <- c.ensureUnlocked(ctx) }()
		waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
		waiterCtx, cancelWaiter := context.WithCancel(ctx)
		t.Cleanup(cancelWaiter)
		waiterDone := make(chan error, 1)
		go func() { waiterDone <- c.ensureUnlocked(waiterCtx) }()
		waitForTestSignal(t, ctx, hookEntered.channel, "blocked waiter hook")
		prompter.releasePrompt()
		if err := waitForTestError(t, ctx, ownerDone, "owner flight result"); !errors.Is(err, ErrUserCancelled) {
			t.Fatalf("owner error = %v, want ErrUserCancelled", err)
		}
		cancelWaiter()
		hookRelease.trigger()
		select {
		case err := <-waiterDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("waiter error = %v, want context.Canceled", err)
			}
		case <-ctx.Done():
			t.Fatalf("waiter did not return: %v", ctx.Err())
		}
	})
}

func TestEnsureUnlocked_OwnerCancellationIsShared(t *testing.T) {
	const callers = 5
	ctx, cancelOuter := context.WithTimeout(context.Background(), time.Second)
	defer cancelOuter()
	var unlockCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
			return
		}
		unlockCalls.Add(1)
	}))
	t.Cleanup(ts.Close)

	prompter := &flightPrompter{entered: make(chan struct{}), release: make(chan struct{}), sequence: []flightPromptResult{{password: "password"}}}
	t.Cleanup(prompter.releasePrompt)
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c)
	joined := newTestSignal()
	var joiners atomic.Int32
	c.flightWaiterHook = func(*unlockFlight) {
		if joiners.Add(1) == callers-1 {
			joined.trigger()
		}
	}
	ownerCtx, cancelOwner := context.WithCancel(ctx)
	t.Cleanup(cancelOwner)
	results := make([]error, callers)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0] = c.ensureUnlocked(ownerCtx)
	}()
	waitForTestSignal(t, ctx, prompter.entered, "owner prompt")
	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = c.ensureUnlocked(ctx)
		}(i)
	}
	waitForTestSignal(t, ctx, joined.channel, "joined callers")
	cancelOwner()
	prompter.releasePrompt()
	waitForEnsureResults(t, ctx, &wg)

	for i, err := range results {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("caller %d error = %v, want context.Canceled", i, err)
		}
	}
	if got := prompter.callCount.Load(); got != 1 {
		t.Errorf("prompter calls = %d, want 1", got)
	}
	if got := unlockCalls.Load(); got != 0 {
		t.Errorf("unlock calls = %d, want 0", got)
	}
}

func TestEnsureUnlocked_FailedFlightAllowsLaterIndependentAttempt(t *testing.T) {
	const firstFlightCallers = 5
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	barrier := newStartBarrier(firstFlightCallers)
	var unlockCalls atomic.Int32
	var unlocked atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			if !unlocked.Load() && barrier.count.Load() < barrier.want {
				barrier.handleStatus(w, r)
				return
			}
			status := "locked"
			if unlocked.Load() {
				status = "unlocked"
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"data":{"template":{"status":%q}}}`, status)
		case "/unlock":
			unlockCalls.Add(1)
			unlocked.Store(true)
			_, _ = w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(barrier.releaseStart)

	prompter := &flightPrompter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		sequence: []flightPromptResult{
			{err: ErrUserCancelled},
			{password: "correct"},
		},
	}
	t.Cleanup(prompter.releasePrompt)
	c := clientWithPrompter(ts, prompter, true)
	makeServeHealthy(c)
	joined := newTestSignal()
	var joiners atomic.Int32
	c.flightWaiterHook = func(*unlockFlight) {
		if joiners.Add(1) == firstFlightCallers-1 {
			joined.trigger()
		}
	}
	firstResults := make([]error, firstFlightCallers)
	var firstWG sync.WaitGroup
	for i := range firstResults {
		firstWG.Add(1)
		go func(index int) {
			defer firstWG.Done()
			firstResults[index] = c.ensureUnlocked(ctx)
		}(i)
	}
	releaseConcurrentStart(t, ctx, barrier)
	waitForTestSignal(t, ctx, prompter.entered, "first prompt")
	waitForTestSignal(t, ctx, joined.channel, "first-flight waiters")
	prompter.releasePrompt()
	waitForEnsureResults(t, ctx, &firstWG)
	for i, err := range firstResults {
		if !errors.Is(err, ErrUserCancelled) {
			t.Errorf("first-flight caller %d error = %v, want ErrUserCancelled", i, err)
		}
	}
	if got := joiners.Load(); got != firstFlightCallers-1 {
		t.Fatalf("first-flight joiners = %d, want %d", got, firstFlightCallers-1)
	}

	c.flightWaiterHook = nil
	if err := c.ensureUnlocked(ctx); err != nil {
		t.Fatalf("second independent attempt error = %v, want nil", err)
	}
	locked, err := c.IsLocked(ctx)
	if err != nil {
		t.Fatalf("status after successful unlock error = %v", err)
	}
	if locked {
		t.Fatal("status after successful unlock = locked, want unlocked")
	}
	if got := prompter.callCount.Load(); got != 2 {
		t.Errorf("prompter calls = %d, want 2", got)
	}
	if got := unlockCalls.Load(); got != 1 {
		t.Errorf("unlock calls = %d, want 1", got)
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
	flight := &unlockFlight{done: make(chan struct{})}
	c.unlockFlightMu.Lock()
	c.unlockFlight = flight
	c.unlockFlightMu.Unlock()
	t.Cleanup(func() {
		c.unlockFlightMu.Lock()
		current := c.unlockFlight
		c.unlockFlightMu.Unlock()
		if current == flight {
			c.completeUnlockFlight(flight, nil)
		}
	})
	hookEntered := newTestSignal()
	hookRelease := newTestSignal()
	t.Cleanup(hookRelease.trigger)
	c.flightWaiterHook = func(joined *unlockFlight) {
		if joined != flight {
			t.Errorf("joined flight = %p, want %p", joined, flight)
		}
		hookEntered.trigger()
		<-hookRelease.channel
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() {
		done <- c.ensureUnlocked(ctx)
	}()

	waitForTestSignal(t, context.Background(), hookEntered.channel, "flight waiter hook")
	cancel()
	hookRelease.trigger()
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
	// Only the quick IsLocked should run because a waiter never performs owner work.
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

	// Goroutine A will enter the prompt as the flight owner.
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

func TestUnlock_HTTPBadRequestInvalidMasterPassword(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
	}))
	t.Cleanup(ts.Close)

	c := clientWithPrompter(ts, &mockPrompter{}, true)
	_, err := c.Unlock(context.Background(), "do-not-leak-this-password")
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Unlock() error = %v, want ErrInvalidPassword", err)
	}
	if strings.Contains(err.Error(), "do-not-leak-this-password") {
		t.Fatal("Unlock() error leaked password")
	}
}

func TestEnsureUnlocked_HTTPBadRequestInvalidPasswordNotifiesAndRetries(t *testing.T) {
	var unlockCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_, _ = w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
		case "/unlock":
			if unlockCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"title":"test vault","message":"Vault unlocked","raw":"test-token"}}`))
		}
	}))
	t.Cleanup(ts.Close)

	prompter := &notifierRetryPrompter{retryNotified: make(chan struct{}), releaseRetry: make(chan struct{})}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)
	done := make(chan error, 1)
	go func() { done <- c.ensureUnlocked(context.Background()) }()

	testCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitForTestSignal(t, testCtx, prompter.retryNotified, "retry notifier")
	select {
	case err := <-done:
		t.Fatalf("ensureUnlocked() returned after first HTTP 400: %v", err)
	default:
	}
	close(prompter.releaseRetry)
	if err := waitForTestError(t, testCtx, done, "successful retry"); err != nil {
		t.Fatalf("ensureUnlocked() error = %v, want nil", err)
	}
	if got := prompter.retryCount.Load(); got != 1 {
		t.Errorf("retry notifications = %d, want 1", got)
	}
	if got := unlockCalls.Load(); got != 2 {
		t.Errorf("unlock calls = %d, want 2", got)
	}
}

func TestUnlock_HTTPBadRequestOtherMessageRemainsSanitizedAPIError(t *testing.T) {
	const responseBody = `{"success":false,"message":"prefix Invalid master password. secret-body-value","password":"body-password"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(ts.Close)

	c := clientWithPrompter(ts, &mockPrompter{}, true)
	_, err := c.Unlock(context.Background(), "request-password")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Unlock() error = %T %v, want *APIError", err, err)
	}
	for _, secret := range []string{"secret-body-value", "body-password", "request-password"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Unlock() error leaked %q", secret)
		}
	}
}

func TestUnlock_DoesNotClassifyInvalidPasswordMarkerBeyondBodyLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat(" ", maxErrorBody) + `{"message":"Invalid master password."}`))
	}))
	t.Cleanup(ts.Close)

	c := clientWithPrompter(ts, &mockPrompter{}, true)
	_, err := c.Unlock(context.Background(), "request-password")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Unlock() error = %T %v, want *APIError", err, err)
	}
	if errors.Is(err, ErrInvalidPassword) {
		t.Fatal("Unlock() classified marker beyond bounded body as ErrInvalidPassword")
	}
}

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
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"success":false,"message":"Connection to server failed"}`))
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
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("ensureUnlocked() error = %T %v, want wrapped *APIError", err, err)
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
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

type retryCancellationPrompter struct {
	callCount     atomic.Int32
	retryResults  atomic.Int32
	terminalCalls atomic.Int32
	retryReady    chan struct{}
	retryWaiting  chan struct{}
}

func (p *retryCancellationPrompter) PromptForPassword(ctx context.Context, _ string) (string, ResultNotifier, error) {
	if p.callCount.Add(1) == 1 {
		return "wrong", func(_ bool, _ string, retry bool) {
			if retry {
				p.retryResults.Add(1)
				close(p.retryReady)
				return
			}
			p.terminalCalls.Add(1)
		}, nil
	}
	close(p.retryWaiting)
	<-ctx.Done()
	return "", nil, ctx.Err()
}

func TestEnsureUnlocked_OwnerCancellationAfterRetryTerminatesPrompt(t *testing.T) {
	var unlockCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/unlock" {
			unlockCalls.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"success":false,"message":"Invalid master password."}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"template":{"status":"locked"}}}`))
	}))
	t.Cleanup(ts.Close)

	prompter := &retryCancellationPrompter{retryReady: make(chan struct{}), retryWaiting: make(chan struct{})}
	c := clientWithPrompter(ts, prompter, true)
	c.session.maxPasswordRetries = 3
	makeServeHealthy(c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.ensureUnlocked(ctx) }()
	testCtx, testCancel := context.WithTimeout(context.Background(), time.Second)
	defer testCancel()
	waitForTestSignal(t, testCtx, prompter.retryReady, "retry publication")
	waitForTestSignal(t, testCtx, prompter.retryWaiting, "retry wait")
	cancel()

	resultCtx, resultCancel := context.WithTimeout(context.Background(), time.Second)
	defer resultCancel()
	if err := waitForTestError(t, resultCtx, done, "cancelled owner"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ensureUnlocked() error = %v, want context.Canceled", err)
	}
	if got := prompter.callCount.Load(); got != 2 {
		t.Fatalf("prompt calls = %d, want 2", got)
	}
	if got := unlockCalls.Load(); got != 1 {
		t.Fatalf("unlock calls = %d, want 1", got)
	}
	if got := prompter.retryResults.Load(); got != 1 {
		t.Fatalf("retry results = %d, want 1", got)
	}
	if got := prompter.terminalCalls.Load(); got != 1 {
		t.Fatalf("terminal cleanup calls = %d, want 1", got)
	}
}

func TestDoRequest_TruncatesLargeErrorBody(t *testing.T) {
	// Create a large error body (5000 bytes, exceeding maxErrorBody of 4096)
	largeBody := strings.Repeat("x", 5000)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(largeBody))
	}))
	defer ts.Close()

	c := NewClient(0)
	c.baseURL = ts.URL
	c.httpClient = &http.Client{Timeout: 5 * time.Second}

	// Call a public method that uses doRequest
	_, err := c.Status(context.Background())
	if err == nil {
		t.Fatal("expected error from bad request")
	}

	// Assert error is an APIError
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}

	// Assert DebugDetails contains truncation indicator
	details := apiErr.DebugDetails()
	if !strings.Contains(details, "truncated") {
		t.Errorf("DebugDetails() should contain 'truncated' indicator, got: %q", details)
	}

	// Assert the body was actually truncated (should be around 4096 bytes plus marker)
	if len(details) > 4200 {
		t.Errorf("DebugDetails() length = %d, expected truncated to ~4096 bytes", len(details))
	}
}

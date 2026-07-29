package noctalia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testPromptRequest() KeyringRequest {
	return KeyringRequest{
		Type:    MessageTypeRequest,
		Cookie:  strings.Repeat("a", 32),
		Title:   "Bitwarden Keyring",
		Message: "Enter master password",
	}
}

func bridgeEndpoint(bridge *promptBridge, path string) string {
	return "http://" + bridge.listener.Addr().String() + path
}

func newAuthorizedBridgeRequest(t *testing.T, bridge *promptBridge, method, path string, body io.Reader) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, bridgeEndpoint(bridge, path), body)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer "+bridge.token)
	return request
}

func doAuthorizedBridgeRequest(t *testing.T, bridge *promptBridge, method, path, contentType string, body io.Reader) *http.Response {
	t.Helper()
	request := newAuthorizedBridgeRequest(t, bridge, method, path, body)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	responseRecorder := httptest.NewRecorder()
	bridge.server.Handler.ServeHTTP(responseRecorder, request)
	return responseRecorder.Result()
}

func encodeBridgeResponse(t *testing.T, response KeyringResponse) *bytes.Reader {
	t.Helper()
	contents, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return bytes.NewReader(contents)
}

func testKeyringResponse(bridge *promptBridge, result, password string) KeyringResponse {
	return KeyringResponse{Type: MessageTypeResponse, ID: bridge.request.Cookie, Result: result, Password: password}
}

func waitForPendingResult(t *testing.T, bridge *promptBridge) {
	t.Helper()
	bridge.mu.Lock()
	if bridge.pendingResult != nil {
		bridge.mu.Unlock()
		return
	}
	ready := bridge.pendingReady
	bridge.mu.Unlock()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending result")
	}
}

type blockingBridgeResponseWriter struct {
	header  http.Header
	started chan struct{}
	release chan struct{}
	once    sync.Once
	err     error
}

type errorBridgeResponseWriter struct {
	header http.Header
	err    error
}

type gatedRequestBody struct {
	reader  *bytes.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGatedRequestBody(contents []byte) *gatedRequestBody {
	return &gatedRequestBody{
		reader:  bytes.NewReader(contents),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *gatedRequestBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.reader.Read(p)
}

func (b *gatedRequestBody) Close() error { return nil }

func (w *errorBridgeResponseWriter) Header() http.Header { return w.header }

func (w *errorBridgeResponseWriter) WriteHeader(int) {}

func (w *errorBridgeResponseWriter) Write([]byte) (int, error) { return 0, w.err }

func newBlockingBridgeResponseWriter() *blockingBridgeResponseWriter {
	return &blockingBridgeResponseWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingBridgeResponseWriter) Header() http.Header { return w.header }

func (w *blockingBridgeResponseWriter) WriteHeader(int) {}

func (w *blockingBridgeResponseWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func newTestPromptBridge(t *testing.T, request KeyringRequest) *promptBridge {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if err := os.Chmod(os.Getenv("XDG_RUNTIME_DIR"), 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}

	bridge, err := newPromptBridge(request)
	if err != nil {
		t.Fatalf("newPromptBridge() error = %v", err)
	}
	t.Cleanup(func() { _ = bridge.Close() })
	return bridge
}

func TestPromptBridgeDescriptorCreatesSecureDescriptor(t *testing.T) {
	request := testPromptRequest()
	bridge := newTestPromptBridge(t, request)

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	bridgeDir := filepath.Join(runtimeDir, "bitwarden-keyring")

	directoryInfo, err := os.Stat(bridgeDir)
	if err != nil {
		t.Fatalf("stat bridge directory: %v", err)
	}
	if directoryInfo.Mode().Perm() != 0700 {
		t.Errorf("bridge directory mode = %04o, want 0700", directoryInfo.Mode().Perm())
	}

	descriptorInfo, err := os.Stat(bridge.descriptor)
	if err != nil {
		t.Fatalf("stat descriptor: %v", err)
	}
	if descriptorInfo.Mode().Perm() != 0600 {
		t.Errorf("descriptor mode = %04o, want 0600", descriptorInfo.Mode().Perm())
	}

	contents, err := os.ReadFile(bridge.descriptor)
	if err != nil {
		t.Fatalf("read descriptor: %v", err)
	}
	var descriptor bridgeDescriptor
	if err := json.Unmarshal(contents, &descriptor); err != nil {
		t.Fatalf("decode descriptor: %v", err)
	}
	if descriptor.Version != 1 || descriptor.RequestID != request.Cookie {
		t.Errorf("descriptor identity is invalid")
	}
	if descriptor.BaseURL != "http://"+bridge.listener.Addr().String() {
		t.Errorf("descriptor base URL = %q, want listener URL", descriptor.BaseURL)
	}
	if len(descriptor.Token) != 64 || strings.Trim(descriptor.Token, "0123456789abcdef") != "" {
		t.Errorf("descriptor token has invalid format")
	}

	tcpAddress, ok := bridge.listener.Addr().(*net.TCPAddr)
	if !ok || !tcpAddress.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("listener address = %v, want 127.0.0.1", bridge.listener.Addr())
	}
}

func TestPromptBridgeDescriptorTokensAreDistinct(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if err := os.Chmod(os.Getenv("XDG_RUNTIME_DIR"), 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}

	firstRequest := testPromptRequest()
	secondRequest := firstRequest
	secondRequest.Cookie = strings.Repeat("b", 32)

	first, err := newPromptBridge(firstRequest)
	if err != nil {
		t.Fatalf("newPromptBridge(first) error = %v", err)
	}
	defer first.Close()
	second, err := newPromptBridge(secondRequest)
	if err != nil {
		t.Fatalf("newPromptBridge(second) error = %v", err)
	}
	defer second.Close()

	if first.token == second.token {
		t.Errorf("distinct bridges generated the same token")
	}
	for _, token := range []string{first.token, second.token} {
		if len(token) != 64 || strings.Trim(token, "0123456789abcdef") != "" {
			t.Errorf("bridge token has invalid format")
		}
	}
}

func TestPromptBridgeDescriptorRejectsInvalidCookie(t *testing.T) {
	invalidCookies := []string{"", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("g", 32)}
	for _, cookie := range invalidCookies {
		t.Run(cookie, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			request := testPromptRequest()
			request.Cookie = cookie
			if _, err := newPromptBridge(request); err == nil {
				t.Error("newPromptBridge() error = nil, want invalid cookie error")
			}
		})
	}
}

func TestPromptBridgeDescriptorRejectsInvalidRuntimeDirectory(t *testing.T) {
	for _, runtimeDir := range []string{"", "relative-runtime"} {
		t.Run(runtimeDir, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			if _, err := newPromptBridge(testPromptRequest()); err == nil {
				t.Error("newPromptBridge() error = nil, want invalid runtime directory error")
			}
		})
	}
}

func TestPromptBridgeDescriptorCreatesChildWithExactMode(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	childInfo, err := os.Stat(filepath.Dir(bridge.descriptor))
	if err != nil {
		t.Fatalf("stat child directory: %v", err)
	}
	if childInfo.Mode().Perm() != 0700 {
		t.Errorf("child directory mode = %04o, want 0700", childInfo.Mode().Perm())
	}
}

func TestPromptBridgeDescriptorRejectsInvalidChildPaths(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, child string)
	}{
		{
			name: "non-directory",
			setup: func(t *testing.T, child string) {
				if err := os.WriteFile(child, []byte("not a directory"), 0600); err != nil {
					t.Fatalf("write child path: %v", err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, child string) {
				realChild := child + "-real"
				if err := os.Mkdir(realChild, 0700); err != nil {
					t.Fatalf("mkdir real child: %v", err)
				}
				if err := os.Symlink(realChild, child); err != nil {
					t.Fatalf("symlink child: %v", err)
				}
			},
		},
		{
			name: "wrong-mode",
			setup: func(t *testing.T, child string) {
				if err := os.Mkdir(child, 0755); err != nil {
					t.Fatalf("mkdir child: %v", err)
				}
				if err := os.Chmod(child, 0755); err != nil {
					t.Fatalf("chmod child: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtimeDir := t.TempDir()
			if err := os.Chmod(runtimeDir, 0700); err != nil {
				t.Fatalf("chmod runtime directory: %v", err)
			}
			child := filepath.Join(runtimeDir, "bitwarden-keyring")
			test.setup(t, child)
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			if _, err := newPromptBridge(testPromptRequest()); err == nil {
				t.Error("newPromptBridge() error = nil, want invalid child path error")
			}
		})
	}
}

func TestPromptBridgeDescriptorRejectsWrongOwnerChild(t *testing.T) {
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}
	child := filepath.Join(runtimeDir, "bitwarden-keyring")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatalf("mkdir child: %v", err)
	}
	otherUID := os.Getuid() + 1
	if otherUID == os.Getuid() {
		otherUID = os.Getuid() - 1
	}
	if err := os.Chown(child, otherUID, -1); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			t.Skipf("changing child owner requires unavailable privilege or platform support: %v", err)
		}
		t.Fatalf("chown child: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	if _, err := newPromptBridge(testPromptRequest()); err == nil {
		t.Error("newPromptBridge() error = nil, want wrong owner error")
	}
}

func TestPromptBridgeDescriptorRejectsSymlinkedRuntime(t *testing.T) {
	root := t.TempDir()
	realRuntime := filepath.Join(root, "real-runtime")
	if err := os.Mkdir(realRuntime, 0700); err != nil {
		t.Fatalf("mkdir real runtime: %v", err)
	}
	runtimeLink := filepath.Join(root, "runtime-link")
	if err := os.Symlink(realRuntime, runtimeLink); err != nil {
		t.Fatalf("symlink runtime: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeLink)

	if _, err := newPromptBridge(testPromptRequest()); err == nil {
		t.Error("newPromptBridge() error = nil, want symlink rejection")
	}
}

func TestPromptBridgeDescriptorRejectsUnsafeDirectories(t *testing.T) {
	t.Run("runtime", func(t *testing.T) {
		runtimeDir := t.TempDir()
		if err := os.Chmod(runtimeDir, 0770); err != nil {
			t.Fatalf("chmod runtime: %v", err)
		}
		t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
		if _, err := newPromptBridge(testPromptRequest()); err == nil {
			t.Error("newPromptBridge() error = nil, want unsafe runtime rejection")
		}
	})

	t.Run("child", func(t *testing.T) {
		runtimeDir := t.TempDir()
		if err := os.Chmod(runtimeDir, 0700); err != nil {
			t.Fatalf("chmod runtime directory: %v", err)
		}
		child := filepath.Join(runtimeDir, "bitwarden-keyring")
		if err := os.Mkdir(child, 0770); err != nil {
			t.Fatalf("mkdir child: %v", err)
		}
		if err := os.Chmod(child, 0770); err != nil {
			t.Fatalf("chmod child: %v", err)
		}
		t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
		if _, err := newPromptBridge(testPromptRequest()); err == nil {
			t.Error("newPromptBridge() error = nil, want unsafe child rejection")
		}
	})
}

func TestPromptBridgeDescriptorRejectsCollision(t *testing.T) {
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}
	child := filepath.Join(runtimeDir, "bitwarden-keyring")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatalf("mkdir child: %v", err)
	}
	descriptorPath := filepath.Join(child, "noctalia-"+strings.Repeat("a", 32)+".json")
	if err := os.WriteFile(descriptorPath, []byte("replacement"), 0600); err != nil {
		t.Fatalf("write descriptor collision: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	if _, err := newPromptBridge(testPromptRequest()); err == nil {
		t.Error("newPromptBridge() error = nil, want descriptor collision error")
	}
}

func TestPromptBridgeDescriptorRejectsWriteFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write through directory permissions")
	}
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}
	child := filepath.Join(runtimeDir, "bitwarden-keyring")
	if err := os.Mkdir(child, 0500); err != nil {
		t.Fatalf("mkdir child: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	if _, err := newPromptBridge(testPromptRequest()); err == nil {
		t.Error("newPromptBridge() error = nil, want descriptor write error")
	}
}

func TestPromptBridgeDescriptorSyncFailureCleansResources(t *testing.T) {
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	injectedErr := errors.New("injected descriptor sync failure")
	var descriptorFile *os.File
	bridge, err := newPromptBridgeWithDescriptorWriter(testPromptRequest(), func(file *os.File, descriptor bridgeDescriptor) error {
		descriptorFile = file
		return writeBridgeDescriptorWithSync(file, descriptor, func(*os.File) error {
			return injectedErr
		})
	})
	if !errors.Is(err, injectedErr) {
		t.Fatalf("newPromptBridgeWithDescriptorWriter() error = %v, want injected sync error", err)
	}
	if bridge != nil {
		t.Fatal("newPromptBridgeWithDescriptorWriter() returned bridge after sync failure")
	}
	if descriptorFile == nil {
		t.Fatal("descriptor writer was not invoked")
	}
	if _, statErr := descriptorFile.Stat(); statErr == nil {
		t.Error("descriptor file remains open after sync failure")
	}

	child := filepath.Join(runtimeDir, "bitwarden-keyring")
	entries, err := os.ReadDir(child)
	if err != nil {
		t.Fatalf("read bridge directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("bridge directory contains %d entries after sync failure", len(entries))
	}

	descriptorPath := filepath.Join(child, "noctalia-"+testPromptRequest().Cookie+".json")
	if _, err := os.Lstat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("descriptor path stat error = %v, want not exists", err)
	}
}

func TestPromptBridgeWaitResponseTimeoutDisablesLateResponse(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	if _, err := bridge.waitResponse(context.Background(), time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("waitResponse() error = %v, want ErrTimeout", err)
	}
	if _, err := bridge.waitResponse(context.Background(), time.Second); !errors.Is(err, ErrTimeout) {
		t.Errorf("second waitResponse() error = %v, want ErrTimeout", err)
	}
	response := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, testKeyringResponse(bridge, ResultOK, "late")))
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Errorf("late response status = %d, want %d", response.StatusCode, http.StatusConflict)
	}
}

func TestPromptBridgeTerminalBeforeReservationPreservesTerminalError(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	ctx, cancel := context.WithCancel(context.Background())
	waitDone := make(chan error, 1)
	go func() {
		_, err := bridge.waitResponse(ctx, time.Second)
		waitDone <- err
	}()

	contents, err := json.Marshal(testKeyringResponse(bridge, ResultOK, "late"))
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	body := newGatedRequestBody(contents)
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", body)
	request.Header.Set("Content-Type", "application/json")
	handlerDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		bridge.server.Handler.ServeHTTP(recorder, request)
		handlerDone <- recorder.Code
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response decode")
	}
	cancel()
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("waitResponse() error = %v, want ErrCancelled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for terminal wait")
	}
	close(body.release)
	select {
	case status := <-handlerDone:
		if status != http.StatusConflict {
			t.Errorf("terminal response status = %d, want %d", status, http.StatusConflict)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for terminal response")
	}
	if _, err := bridge.waitResponse(context.Background(), time.Second); !errors.Is(err, ErrCancelled) {
		t.Errorf("later waitResponse() error = %v, want original ErrCancelled", err)
	}
}

func TestPromptBridgeReservationWinsCancellationWithHook(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	reserved := make(chan struct{})
	release := make(chan struct{})
	bridge.responseReservationHook = func() {
		close(reserved)
		<-release
	}
	ctx, cancel := context.WithCancel(context.Background())
	waitDone := make(chan KeyringResponse, 1)
	waitErr := make(chan error, 1)
	go func() {
		response, err := bridge.waitResponse(ctx, time.Second)
		waitDone <- response
		waitErr <- err
	}()
	response := testKeyringResponse(bridge, ResultOK, "password")
	contents, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	handlerDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		request := newAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", bytes.NewReader(contents))
		request.Header.Set("Content-Type", "application/json")
		bridge.server.Handler.ServeHTTP(recorder, request)
		handlerDone <- recorder.Code
	}()
	select {
	case <-reserved:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response reservation")
	}
	cancel()
	select {
	case got := <-waitDone:
		if got != response {
			t.Errorf("waitResponse() = %#v, want %#v", got, response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reserved response")
	}
	if err := <-waitErr; err != nil {
		t.Fatalf("waitResponse() error = %v, want nil", err)
	}
	close(release)
	select {
	case status := <-handlerDone:
		if status != http.StatusAccepted {
			t.Errorf("reserved response status = %d, want %d", status, http.StatusAccepted)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reserved response handler")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.responseState != responseStateConsumed || bridge.responseSlot != (KeyringResponse{}) {
		t.Errorf("response state after consume = state %v slot=%#v", bridge.responseState, bridge.responseSlot)
	}
}

func TestPromptBridgeReservationWinsCloseWithHook(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	reserved := make(chan struct{})
	release := make(chan struct{})
	bridge.responseReservationHook = func() {
		close(reserved)
		<-release
	}
	response := testKeyringResponse(bridge, ResultOK, "password")
	contents, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	handlerDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		request := newAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", bytes.NewReader(contents))
		request.Header.Set("Content-Type", "application/json")
		bridge.server.Handler.ServeHTTP(recorder, request)
		handlerDone <- recorder.Code
	}()
	select {
	case <-reserved:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response reservation")
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	close(release)
	select {
	case status := <-handlerDone:
		if status != http.StatusAccepted {
			t.Errorf("reserved response after close status = %d, want %d", status, http.StatusAccepted)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response handler")
	}
	got, err := bridge.waitResponse(context.Background(), time.Second)
	if err != nil || got != response {
		t.Errorf("waitResponse() = %#v, %v, want reserved response", got, err)
	}
}

func TestPromptBridgeWaitResponseCancellationDisablesLateResponse(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bridge.waitResponse(ctx, time.Second); !errors.Is(err, ErrCancelled) {
		t.Fatalf("waitResponse() error = %v, want ErrCancelled", err)
	}
	response := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, testKeyringResponse(bridge, ResultOK, "late")))
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Errorf("late response status = %d, want %d", response.StatusCode, http.StatusConflict)
	}
}

func TestPromptBridgeWaitResponseCancellationWinsInFlightResponse(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	ctx, cancel := context.WithCancel(context.Background())
	waitDone := make(chan error, 1)
	go func() {
		_, err := bridge.waitResponse(ctx, time.Second)
		waitDone <- err
	}()

	contents, err := json.Marshal(testKeyringResponse(bridge, ResultOK, "late"))
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	body := newGatedRequestBody(contents)
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", body)
	request.Header.Set("Content-Type", "application/json")
	handlerDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		bridge.server.Handler.ServeHTTP(recorder, request)
		handlerDone <- recorder.Code
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-flight response")
	}
	cancel()
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("waitResponse() error = %v, want ErrCancelled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cancellation")
	}
	close(body.release)
	select {
	case status := <-handlerDone:
		if status != http.StatusConflict {
			t.Errorf("in-flight response status = %d, want %d", status, http.StatusConflict)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-flight response completion")
	}
}

func TestPromptBridgeCloseWinsInFlightResponse(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	contents, err := json.Marshal(testKeyringResponse(bridge, ResultOK, "late"))
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	body := newGatedRequestBody(contents)
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", body)
	request.Header.Set("Content-Type", "application/json")
	handlerDone := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		bridge.server.Handler.ServeHTTP(recorder, request)
		handlerDone <- recorder.Code
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-flight response")
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	close(body.release)
	select {
	case status := <-handlerDone:
		if status != http.StatusGone {
			t.Errorf("in-flight response status = %d, want %d", status, http.StatusGone)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-flight response completion")
	}
}

func TestPromptBridgeRequestReturnsRequestOnlyWithBearerToken(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	client := &http.Client{Timeout: time.Second}
	url := "http://" + bridge.listener.Addr().String() + "/v1/request"

	tests := []struct {
		name       string
		authorize  func(*http.Request)
		remoteAddr string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusNotFound},
		{name: "wrong", authorize: func(request *http.Request) { request.Header.Set("Authorization", "Bearer wrong") }, wantStatus: http.StatusNotFound},
		{name: "duplicate", authorize: func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer "+bridge.token)
			request.Header.Add("Authorization", "Bearer "+bridge.token)
		}, wantStatus: http.StatusNotFound},
		{name: "non-loopback", authorize: func(request *http.Request) { request.Header.Set("Authorization", "Bearer "+bridge.token) }, remoteAddr: "192.0.2.1:1234", wantStatus: http.StatusNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if test.authorize != nil {
				test.authorize(request)
			}
			if test.remoteAddr != "" {
				request = httptest.NewRequest(http.MethodGet, url, nil)
				request.RemoteAddr = test.remoteAddr
				if test.authorize != nil {
					test.authorize(request)
				}
				responseRecorder := httptest.NewRecorder()
				bridge.server.Handler.ServeHTTP(responseRecorder, request)
				if responseRecorder.Code != test.wantStatus {
					t.Errorf("status = %d, want %d", responseRecorder.Code, test.wantStatus)
				}
				return
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("client request: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Errorf("status = %d, want %d", response.StatusCode, test.wantStatus)
			}
		})
	}

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new authorized request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+bridge.token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("authorized request: %v", err)
	}
	defer response.Body.Close()
	var got KeyringRequest
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatalf("decode authorized response: %v", err)
	}
	if response.StatusCode != http.StatusOK || got != testPromptRequest() {
		t.Errorf("authorized response = status %d, request %#v", response.StatusCode, got)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %q, want application/json", response.Header.Get("Content-Type"))
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("cache control = %q, want no-store", response.Header.Get("Cache-Control"))
	}
}

func TestPromptBridgeCloseIsIdempotentAndRemovesDescriptor(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	descriptor := bridge.descriptor
	pathInfo, err := fstatatInfo(int(bridge.directoryFile.Fd()), filepath.Base(descriptor))
	if err != nil {
		t.Fatalf("fstatat descriptor: %v", err)
	}
	descriptorInfo, err := bridge.descriptorFile.Stat()
	if err != nil {
		t.Fatalf("stat retained descriptor: %v", err)
	}
	if !os.SameFile(pathInfo, descriptorInfo) {
		t.Error("nofollow descriptor identity does not match retained descriptor")
	}

	if err := bridge.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := os.Stat(descriptor); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("descriptor stat error = %v, want not exists", err)
	}
}

func TestPromptBridgeCloseReportsFirstCleanupError(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	if err := bridge.descriptorFile.Close(); err != nil {
		t.Fatalf("pre-close descriptor close: %v", err)
	}

	firstErr := bridge.Close()
	if firstErr == nil {
		t.Fatal("first Close() error = nil, want cleanup error")
	}
	secondErr := bridge.Close()
	if secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Errorf("second Close() error = %v, want first error %v", secondErr, firstErr)
	}
}

func TestPromptBridgeClosePreservesDescriptorPathReplacement(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	replacement := []byte("replacement")
	if err := os.Remove(bridge.descriptor); err != nil {
		t.Fatalf("remove descriptor: %v", err)
	}
	if err := os.WriteFile(bridge.descriptor, replacement, 0600); err != nil {
		t.Fatalf("write descriptor replacement: %v", err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	contents, err := os.ReadFile(bridge.descriptor)
	if err != nil {
		t.Fatalf("read descriptor replacement: %v", err)
	}
	if string(contents) != string(replacement) {
		t.Errorf("replacement contents changed")
	}
}

func TestPromptBridgeClosePreservesParentPathReplacement(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	originalChild := filepath.Join(runtimeDir, "bitwarden-keyring")
	backupChild := filepath.Join(runtimeDir, "bitwarden-keyring-old")
	if err := os.Rename(originalChild, backupChild); err != nil {
		t.Fatalf("rename original child: %v", err)
	}
	if err := os.Mkdir(originalChild, 0700); err != nil {
		t.Fatalf("create replacement child: %v", err)
	}
	replacement := []byte("replacement")
	replacementPath := filepath.Join(originalChild, filepath.Base(bridge.descriptor))
	if err := os.WriteFile(replacementPath, replacement, 0600); err != nil {
		t.Fatalf("write parent replacement: %v", err)
	}

	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	contents, err := os.ReadFile(replacementPath)
	if err != nil {
		t.Fatalf("read parent replacement: %v", err)
	}
	if string(contents) != string(replacement) {
		t.Errorf("parent replacement contents changed")
	}
}

func TestPromptBridgeResponseValidationAndDelivery(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	valid := testKeyringResponse(bridge, ResultOK, "password")

	for _, test := range []struct {
		name       string
		content    string
		body       io.Reader
		wantStatus int
	}{
		{name: "missing content type", body: encodeBridgeResponse(t, valid), wantStatus: http.StatusUnsupportedMediaType},
		{name: "wrong content type", content: "text/plain", body: encodeBridgeResponse(t, valid), wantStatus: http.StatusUnsupportedMediaType},
		{name: "malformed JSON", content: "application/json", body: strings.NewReader("{"), wantStatus: http.StatusBadRequest},
		{name: "multiple JSON values", content: "application/json", body: strings.NewReader("{} {}"), wantStatus: http.StatusBadRequest},
		{name: "unknown field", content: "application/json", body: strings.NewReader(`{"type":"keyring_response","id":"` + bridge.request.Cookie + `","result":"ok","password":"password","unknown":true}`), wantStatus: http.StatusBadRequest},
		{name: "wrong type", content: "application/json", body: encodeBridgeResponse(t, KeyringResponse{Type: MessageTypeRequest, ID: bridge.request.Cookie, Result: ResultOK, Password: "password"}), wantStatus: http.StatusBadRequest},
		{name: "wrong ID", content: "application/json", body: encodeBridgeResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: strings.Repeat("b", 32), Result: ResultOK, Password: "password"}), wantStatus: http.StatusBadRequest},
		{name: "wrong result", content: "application/json", body: encodeBridgeResponse(t, testKeyringResponse(bridge, "other", "password")), wantStatus: http.StatusBadRequest},
		{name: "empty ok password", content: "application/json", body: encodeBridgeResponse(t, testKeyringResponse(bridge, ResultOK, "")), wantStatus: http.StatusBadRequest},
		{name: "cancelled password", content: "application/json", body: encodeBridgeResponse(t, testKeyringResponse(bridge, ResultCancelled, "password")), wantStatus: http.StatusBadRequest},
		{name: "confirmed password", content: "application/json", body: encodeBridgeResponse(t, testKeyringResponse(bridge, ResultConfirmed, "password")), wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", test.content, test.body)
			response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Errorf("status = %d, want %d", response.StatusCode, test.wantStatus)
			}
		})
	}

	response := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json; charset=utf-8", encodeBridgeResponse(t, valid))
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("valid response status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	got, err := bridge.waitResponse(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("waitResponse() error = %v", err)
	}
	if got != valid {
		t.Errorf("waitResponse() = %#v, want %#v", got, valid)
	}
}

func TestPromptBridgeDuplicateResponseConcurrentDelivery(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	response := testKeyringResponse(bridge, ResultOK, "password")
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	endpoint := bridgeEndpoint(bridge, "/v1/response")
	token := bridge.token
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
			request.RemoteAddr = "127.0.0.1:1234"
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			bridge.server.Handler.ServeHTTP(recorder, request)
			statuses <- recorder.Code
		}()
	}
	close(start)
	waitGroup.Wait()
	close(statuses)

	statusCounts := map[int]int{}
	for status := range statuses {
		statusCounts[status]++
	}
	if statusCounts[http.StatusAccepted] != 1 || statusCounts[http.StatusConflict] != 1 {
		t.Errorf("concurrent response statuses = %#v, want one 202 and one 409", statusCounts)
	}
	got, err := bridge.waitResponse(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("waitResponse() error = %v", err)
	}
	if got != response {
		t.Errorf("delivered response = %#v, want %#v", got, response)
	}
}

func TestPromptBridgeResponseRejectsUnauthorizedAndOversized(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	valid := testKeyringResponse(bridge, ResultOK, "password")

	unauthorized := httptest.NewRequest(http.MethodPost, bridgeEndpoint(bridge, "/v1/response"), encodeBridgeResponse(t, valid))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorized.RemoteAddr = "127.0.0.1:1234"
	unauthorized.Header.Add("Authorization", "Bearer "+bridge.token)
	unauthorized.Header.Add("Authorization", "Bearer "+bridge.token)
	recorder := httptest.NewRecorder()
	bridge.server.Handler.ServeHTTP(recorder, unauthorized)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("duplicate authorization status = %d, want %d", recorder.Code, http.StatusNotFound)
	}

	oversized := strings.Repeat("a", bridgeBodyLimit+1)
	response := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", strings.NewReader(oversized))
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized response status = %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestPromptBridgeResultDeliveryAndRetry(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Error: "invalid password", Retry: true}
	resultDone := make(chan error, 1)
	go func() { resultDone <- bridge.sendResult(context.Background(), result) }()
	waitForPendingResult(t, bridge)

	response := doAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, "", nil)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("result status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var got KeyringResult
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		response.Body.Close()
		t.Fatalf("decode result: %v", err)
	}
	response.Body.Close()
	if got != result {
		t.Errorf("result = %#v, want %#v", got, result)
	}
	if err := <-resultDone; err != nil {
		t.Fatalf("sendResult() error = %v", err)
	}

	response = doAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, "", nil)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("empty result status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	nextResponse := testKeyringResponse(bridge, ResultOK, "retry-password")
	response = doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, nextResponse))
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Errorf("retry response status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	if _, err := bridge.waitResponse(context.Background(), time.Second); err != nil {
		t.Fatalf("wait retry response: %v", err)
	}
}

func TestPromptBridgeResultValidationAndDuplicateClaims(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
	resultDone := make(chan error, 1)
	go func() { resultDone <- bridge.sendResult(context.Background(), result) }()
	waitForPendingResult(t, bridge)

	for _, query := range []string{"", "?id=", "?id=" + strings.Repeat("b", 32), "?id=" + bridge.request.Cookie + "&id=" + bridge.request.Cookie} {
		response := doAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result"+query, "", nil)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("query %q status = %d, want %d", query, response.StatusCode, http.StatusBadRequest)
		}
	}

	writer := newBlockingBridgeResponseWriter()
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
	firstDone := make(chan struct{})
	go func() {
		bridge.server.Handler.ServeHTTP(writer, request)
		close(firstDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first result writer")
	}
	second := doAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, "", nil)
	second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Errorf("concurrent result status = %d, want %d", second.StatusCode, http.StatusConflict)
	}
	close(writer.release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first result")
	}
	if err := <-resultDone; err != nil {
		t.Fatalf("sendResult() error = %v", err)
	}
}

func TestPromptBridgeWaitResponseCancellationTimeoutAndClose(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bridge.waitResponse(cancelled, time.Second); !errors.Is(err, ErrCancelled) {
		t.Errorf("cancelled wait error = %v, want ErrCancelled", err)
	}
	bridge = newTestPromptBridge(t, testPromptRequest())
	deadline, deadlineCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer deadlineCancel()
	if _, err := bridge.waitResponse(deadline, time.Second); !errors.Is(err, ErrTimeout) {
		t.Errorf("deadline wait error = %v, want ErrTimeout", err)
	}
	if _, err := bridge.waitResponse(context.Background(), time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Errorf("timer wait error = %v, want ErrTimeout", err)
	}

	resultDone := make(chan error, 1)
	go func() {
		resultDone <- bridge.sendResult(context.Background(), KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie})
	}()
	waitForPendingResult(t, bridge)
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-resultDone; !errors.Is(err, ErrSessionClosed) {
		t.Errorf("closed sendResult error = %v, want ErrSessionClosed", err)
	}

	authorized := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/request", nil)
	recorder := httptest.NewRecorder()
	bridge.server.Handler.ServeHTTP(recorder, authorized)
	if recorder.Code != http.StatusGone {
		t.Errorf("closed authorized request status = %d, want %d", recorder.Code, http.StatusGone)
	}
	unauthorized := httptest.NewRequest(http.MethodGet, bridgeEndpoint(bridge, "/v1/request"), nil)
	unauthorized.RemoteAddr = "127.0.0.1:1234"
	recorder = httptest.NewRecorder()
	bridge.server.Handler.ServeHTTP(recorder, unauthorized)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("closed unauthorized request status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestPromptBridgeWaitResponseStaleBufferedResponseLosesToCancellation(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	bridge.mu.Lock()
	bridge.responseState = responseStateAccepting
	bridge.responseSlot = testKeyringResponse(bridge, ResultOK, "stale")
	bridge.mu.Unlock()
	close(bridge.responseNotify)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bridge.waitResponse(ctx, time.Second); !errors.Is(err, ErrCancelled) {
		t.Errorf("stale response wait error = %v, want ErrCancelled", err)
	}
}

func TestPromptBridgeWaitResponseStaleBufferedResponseLosesToClose(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	bridge.mu.Lock()
	bridge.responseState = responseStateAccepting
	bridge.responseSlot = testKeyringResponse(bridge, ResultOK, "stale")
	bridge.mu.Unlock()
	close(bridge.responseNotify)
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := bridge.waitResponse(context.Background(), time.Second); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("stale response after close error = %v, want ErrSessionClosed", err)
	}
}

func TestPromptBridgeTerminalWaitDoesNotConsumeLateResponse(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bridge.waitResponse(ctx, time.Second); !errors.Is(err, ErrCancelled) {
		t.Fatalf("waitResponse() error = %v, want ErrCancelled", err)
	}

	late := testKeyringResponse(bridge, ResultOK, "late")
	bridge.mu.Lock()
	bridge.responseSlot = late
	bridge.mu.Unlock()

	if _, err := bridge.waitResponse(context.Background(), time.Second); !errors.Is(err, ErrCancelled) {
		t.Errorf("later waitResponse() error = %v, want original ErrCancelled", err)
	}
}

func TestPromptBridgeResponseReservationWinsClose(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	response := testKeyringResponse(bridge, ResultOK, "password")
	reply := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, response))
	reply.Body.Close()
	if reply.StatusCode != http.StatusAccepted {
		t.Fatalf("response status = %d, want %d", reply.StatusCode, http.StatusAccepted)
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	got, err := bridge.waitResponse(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("waitResponse() error = %v, want response", err)
	}
	if got != response {
		t.Errorf("waitResponse() = %#v, want %#v", got, response)
	}
}

func TestPromptBridgeResultFinalizationOrdering(t *testing.T) {
	t.Run("finalize first", func(t *testing.T) {
		bridge := newTestPromptBridge(t, testPromptRequest())
		result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
		resultDone := make(chan error, 1)
		go func() { resultDone <- bridge.sendResult(context.Background(), result) }()
		waitForPendingResult(t, bridge)

		request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
		recorder := httptest.NewRecorder()
		bridge.server.Handler.ServeHTTP(recorder, request)
		if err := <-resultDone; err != nil {
			t.Errorf("finalized sendResult() error = %v, want nil", err)
		}
	})

	t.Run("abandon first", func(t *testing.T) {
		bridge := newTestPromptBridge(t, testPromptRequest())
		result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
		ctx, cancel := context.WithCancel(context.Background())
		resultDone := make(chan error, 1)
		go func() { resultDone <- bridge.sendResult(ctx, result) }()
		waitForPendingResult(t, bridge)
		cancel()
		if err := <-resultDone; !errors.Is(err, ErrCancelled) {
			t.Fatalf("abandoned sendResult() error = %v, want ErrCancelled", err)
		}

		request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
		recorder := httptest.NewRecorder()
		bridge.server.Handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNoContent {
			t.Errorf("late result status = %d, want %d", recorder.Code, http.StatusNoContent)
		}
	})
}

func TestPromptBridgeResultCancellationAfterClaimedWrite(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	ctx, cancel := context.WithCancel(context.Background())
	resultDone := make(chan error, 1)
	go func() {
		resultDone <- bridge.sendResult(ctx, KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true})
	}()
	waitForPendingResult(t, bridge)

	writer := newBlockingBridgeResponseWriter()
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
	handlerDone := make(chan struct{})
	go func() {
		bridge.server.Handler.ServeHTTP(writer, request)
		close(handlerDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for claimed result writer")
	}

	cancel()
	select {
	case err := <-resultDone:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("sendResult() error = %v, want ErrCancelled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cancelled sendResult")
	}

	bridge.mu.Lock()
	pendingBeforeRelease := bridge.pendingResult
	stateBeforeRelease := bridge.responseState
	closedBeforeRelease := bridge.closed
	bridge.mu.Unlock()
	if pendingBeforeRelease != nil || stateBeforeRelease != responseStateTerminal || closedBeforeRelease {
		t.Fatalf("state after cancellation = pending=%v responseState=%v closed=%v", pendingBeforeRelease, stateBeforeRelease, closedBeforeRelease)
	}

	close(writer.release)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("timed out releasing result writer")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.pendingResult != pendingBeforeRelease || bridge.responseState != stateBeforeRelease || bridge.closed != closedBeforeRelease {
		t.Errorf("late finishDelivery changed state: pending=%v responseState=%v closed=%v", bridge.pendingResult, bridge.responseState, bridge.closed)
	}
}

func TestPromptBridgeResultCloseAfterClaimedWrite(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	resultDone := make(chan error, 1)
	go func() {
		resultDone <- bridge.sendResult(context.Background(), KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true})
	}()
	waitForPendingResult(t, bridge)

	writer := newBlockingBridgeResponseWriter()
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
	handlerDone := make(chan struct{})
	go func() {
		bridge.server.Handler.ServeHTTP(writer, request)
		close(handlerDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for claimed result writer")
	}

	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-resultDone:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("sendResult() error = %v, want ErrSessionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for closed sendResult")
	}

	bridge.mu.Lock()
	pendingBeforeRelease := bridge.pendingResult
	stateBeforeRelease := bridge.responseState
	closedBeforeRelease := bridge.closed
	bridge.mu.Unlock()
	if pendingBeforeRelease != nil || stateBeforeRelease != responseStateTerminal || !closedBeforeRelease {
		t.Fatalf("state after close = pending=%v responseState=%v closed=%v", pendingBeforeRelease, stateBeforeRelease, closedBeforeRelease)
	}

	close(writer.release)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("timed out releasing result writer")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.pendingResult != pendingBeforeRelease || bridge.responseState != stateBeforeRelease || bridge.closed != closedBeforeRelease {
		t.Errorf("late finishDelivery changed state: pending=%v responseState=%v closed=%v", bridge.pendingResult, bridge.responseState, bridge.closed)
	}
}

func TestPromptBridgeLateResultWriterCannotMutateAbandonedState(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
	ctx, cancel := context.WithCancel(context.Background())
	resultDone := make(chan error, 1)
	go func() { resultDone <- bridge.sendResult(ctx, result) }()
	waitForPendingResult(t, bridge)
	cancel()
	if err := <-resultDone; !errors.Is(err, ErrCancelled) {
		t.Fatalf("abandoned sendResult() error = %v, want ErrCancelled", err)
	}

	request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
	response := httptest.NewRecorder()
	bridge.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Errorf("late result status = %d, want %d", response.Code, http.StatusNoContent)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.pendingResult != nil || bridge.responseState != responseStateTerminal {
		t.Errorf("late writer mutated bridge state: pending=%v responseState=%v", bridge.pendingResult, bridge.responseState)
	}
}

func TestPromptBridgeRetryEnablesExactlyOneResponse(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Retry: true}
	resultDone := make(chan error, 1)
	go func() { resultDone <- bridge.sendResult(context.Background(), result) }()
	waitForPendingResult(t, bridge)
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
	recorder := httptest.NewRecorder()
	bridge.server.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry result status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if err := <-resultDone; err != nil {
		t.Fatalf("retry sendResult() error = %v", err)
	}

	response := testKeyringResponse(bridge, ResultOK, "retry")
	first := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, response))
	first.Body.Close()
	second := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, response))
	second.Body.Close()
	if first.StatusCode != http.StatusAccepted || second.StatusCode != http.StatusConflict {
		t.Errorf("retry response statuses = %d, %d, want 202, 409", first.StatusCode, second.StatusCode)
	}
	if _, err := bridge.waitResponse(context.Background(), time.Second); err != nil {
		t.Fatalf("wait retry response: %v", err)
	}
}

func TestPromptBridgeDuplicateSendResultCancellation(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- bridge.sendResult(ctx, result) }()
	waitForPendingResult(t, bridge)
	cancel()
	if err := <-firstDone; !errors.Is(err, ErrCancelled) {
		t.Errorf("cancelled sendResult() error = %v, want ErrCancelled", err)
	}

	pendingDone := make(chan error, 1)
	go func() { pendingDone <- bridge.sendResult(context.Background(), result) }()
	waitForPendingResult(t, bridge)
	if err := bridge.sendResult(context.Background(), result); err == nil {
		t.Error("duplicate sendResult() error = nil, want duplicate error")
	}
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-pendingDone; !errors.Is(err, ErrSessionClosed) {
		t.Errorf("closed pending sendResult() error = %v, want ErrSessionClosed", err)
	}
}

func TestPromptBridgeResponseResultAndDuplicateBehavior(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	cancelled := testKeyringResponse(bridge, ResultCancelled, "")
	response := doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, cancelled))
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("cancelled response status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	if got, err := bridge.waitResponse(context.Background(), time.Second); err != nil || got != cancelled {
		t.Fatalf("cancelled wait = %#v, %v", got, err)
	}
	response = doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, cancelled))
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Errorf("duplicate response status = %d, want %d", response.StatusCode, http.StatusConflict)
	}

	terminal := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
	resultDone := make(chan error, 1)
	go func() { resultDone <- bridge.sendResult(context.Background(), terminal) }()
	waitForPendingResult(t, bridge)
	response = doAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, "", nil)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("terminal result status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if err := <-resultDone; err != nil {
		t.Fatalf("terminal sendResult() error = %v", err)
	}
	response = doAuthorizedBridgeRequest(t, bridge, http.MethodPost, "/v1/response", "application/json", encodeBridgeResponse(t, cancelled))
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Errorf("post-terminal response status = %d, want %d", response.StatusCode, http.StatusConflict)
	}
}

func TestPromptBridgeClosedResponseAndResultAreGoneAfterAuthentication(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	validResponse := testKeyringResponse(bridge, ResultCancelled, "")
	for _, test := range []struct {
		name   string
		path   string
		method string
		body   io.Reader
	}{
		{name: "response", path: "/v1/response", method: http.MethodPost, body: encodeBridgeResponse(t, validResponse)},
		{name: "result", path: "/v1/result?id=" + bridge.request.Cookie, method: http.MethodGet},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := newAuthorizedBridgeRequest(t, bridge, test.method, test.path, test.body)
			if test.name == "response" {
				request.Header.Set("Content-Type", "application/json")
			}
			recorder := httptest.NewRecorder()
			bridge.server.Handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusGone {
				t.Errorf("closed %s status = %d, want %d", test.name, recorder.Code, http.StatusGone)
			}
		})
	}
}

func TestPromptBridgeResultWriterFailureIsDeliveredExactly(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	result := KeyringResult{Type: MessageTypeResult, ID: bridge.request.Cookie, Success: true}
	writerError := errors.New("writer failed")
	resultDone := make(chan error, 1)
	go func() { resultDone <- bridge.sendResult(context.Background(), result) }()
	waitForPendingResult(t, bridge)

	writer := &errorBridgeResponseWriter{header: make(http.Header), err: writerError}
	request := newAuthorizedBridgeRequest(t, bridge, http.MethodGet, "/v1/result?id="+bridge.request.Cookie, nil)
	bridge.server.Handler.ServeHTTP(writer, request)
	if err := <-resultDone; !errors.Is(err, writerError) {
		t.Errorf("sendResult() error = %v, want writer error", err)
	}
}

func TestPromptBridgeSendResultRejectsWrongTypeAndID(t *testing.T) {
	bridge := newTestPromptBridge(t, testPromptRequest())
	for _, result := range []KeyringResult{
		{Type: MessageTypeRequest, ID: bridge.request.Cookie},
		{Type: MessageTypeResult, ID: strings.Repeat("b", 32)},
	} {
		if err := bridge.sendResult(context.Background(), result); err == nil {
			t.Errorf("sendResult(%#v) error = nil, want validation error", result)
		}
		bridge.mu.Lock()
		pending := bridge.pendingResult
		bridge.mu.Unlock()
		if pending != nil {
			t.Errorf("invalid result published pending delivery: %#v", pending)
		}
	}
}

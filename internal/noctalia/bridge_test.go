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
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bridge.mu.Lock()
		pending := bridge.pendingResult != nil
		bridge.mu.Unlock()
		if pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for pending result")
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

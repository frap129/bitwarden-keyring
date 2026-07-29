package noctalia

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testPollInterval = 5 * time.Millisecond
	testPollDeadline = time.Second
)

type commandCall struct {
	name string
	args []string
}

type testBridge struct {
	cookie     string
	descriptor bridgeDescriptor
	client     *http.Client
}

func newTestRuntime(t *testing.T) string {
	t.Helper()
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0700); err != nil {
		t.Fatalf("chmod runtime directory: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	return runtimeDir
}

func newTestClient(t *testing.T, timeout time.Duration) (*Client, <-chan commandCall) {
	t.Helper()
	calls := make(chan commandCall, 1)
	runner := func(_ context.Context, name string, args ...string) error {
		calls <- commandCall{name: name, args: append([]string(nil), args...)}
		return nil
	}
	return NewClient(WithCommandRunner(runner), WithTimeout(timeout)), calls
}

func waitForCommand(t *testing.T, calls <-chan commandCall) commandCall {
	t.Helper()
	var call commandCall
	eventually(t, func() bool {
		select {
		case call = <-calls:
			return true
		default:
			return false
		}
	})
	return call
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(testPollDeadline)
	defer deadline.Stop()
	ticker := time.NewTicker(testPollInterval)
	defer ticker.Stop()

	if condition() {
		return
	}
	for {
		select {
		case <-deadline.C:
			t.Fatal("condition was not satisfied before deadline")
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

func descriptorPath(runtimeDir, cookie string) string {
	return filepath.Join(runtimeDir, "bitwarden-keyring", "noctalia-"+cookie+".json")
}

func readTestDescriptor(runtimeDir, cookie string) (bridgeDescriptor, error) {
	contents, err := os.ReadFile(descriptorPath(runtimeDir, cookie))
	if err != nil {
		return bridgeDescriptor{}, err
	}
	var descriptor bridgeDescriptor
	if err := json.Unmarshal(contents, &descriptor); err != nil {
		return bridgeDescriptor{}, err
	}
	return descriptor, nil
}

func newTestBridge(t *testing.T, call commandCall) *testBridge {
	t.Helper()
	if len(call.args) == 0 {
		t.Fatal("command has no cookie argument")
	}
	cookie := call.args[len(call.args)-1]
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	var descriptor bridgeDescriptor
	eventually(t, func() bool {
		var err error
		descriptor, err = readTestDescriptor(runtimeDir, cookie)
		return err == nil
	})
	return &testBridge{cookie: cookie, descriptor: descriptor, client: &http.Client{Timeout: 100 * time.Millisecond}}
}

func (b *testBridge) do(t *testing.T, method, path string, body io.Reader, contentType string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, b.descriptor.BaseURL+path, body)
	if err != nil {
		t.Fatalf("new HTTP request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+b.descriptor.Token)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	return response
}

func (b *testBridge) getRequest(t *testing.T) KeyringRequest {
	t.Helper()
	var request KeyringRequest
	eventually(t, func() bool {
		response := b.do(t, http.MethodGet, "/v1/request", nil, "")
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return false
		}
		return json.NewDecoder(response.Body).Decode(&request) == nil
	})
	return request
}

func (b *testBridge) postResponse(t *testing.T, response KeyringResponse) {
	t.Helper()
	contents, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	reply := b.do(t, http.MethodPost, "/v1/response", strings.NewReader(string(contents)), "application/json")
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusAccepted {
		t.Fatalf("response status = %d, want %d", reply.StatusCode, http.StatusAccepted)
	}
}

func reserveBridgeResponse(bridge *promptBridge, response KeyringResponse) {
	bridge.mu.Lock()
	bridge.responseSlot = response
	bridge.responseState = responseStateReserved
	bridge.responseNotify = make(chan struct{})
	notify := bridge.responseNotify
	bridge.mu.Unlock()
	close(notify)
}

func (b *testBridge) pollResult(t *testing.T) KeyringResult {
	t.Helper()
	var result KeyringResult
	eventually(t, func() bool {
		response := b.do(t, http.MethodGet, "/v1/result?id="+b.cookie, nil, "")
		defer response.Body.Close()
		if response.StatusCode == http.StatusNoContent {
			return false
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("result status = %d, want %d or %d", response.StatusCode, http.StatusOK, http.StatusNoContent)
		}
		return json.NewDecoder(response.Body).Decode(&result) == nil
	})
	return result
}

func waitForClientPendingResult(t *testing.T, bridge *promptBridge) {
	t.Helper()
	eventually(t, func() bool {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		return bridge.pendingResult != nil
	})
}

func assertDescriptorRemoved(t *testing.T, runtimeDir, cookie string) {
	t.Helper()
	eventually(t, func() bool {
		_, err := os.Stat(descriptorPath(runtimeDir, cookie))
		return errors.Is(err, os.ErrNotExist)
	})
}

func commandArgs(t *testing.T, call commandCall, cookie string) {
	t.Helper()
	if call.name != DefaultExecutable {
		t.Errorf("command name = %q, want %q", call.name, DefaultExecutable)
	}
	want := []string{"msg", "plugin", DefaultPluginEntry, "all", MessageTypeRequest, cookie}
	if len(call.args) != len(want) {
		t.Fatalf("command args = %#v, want %#v", call.args, want)
	}
	for index := range want {
		if call.args[index] != want[index] {
			t.Errorf("command args[%d] = %q, want %q", index, call.args[index], want[index])
		}
	}
}

func TestNewClientDefaultsAndTimeoutOverride(t *testing.T) {
	client := NewClient()
	if client.executable != DefaultExecutable {
		t.Errorf("executable = %q, want %q", client.executable, DefaultExecutable)
	}
	if client.pluginEntry != DefaultPluginEntry {
		t.Errorf("plugin entry = %q, want %q", client.pluginEntry, DefaultPluginEntry)
	}
	if client.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", client.timeout, DefaultTimeout)
	}
	if client.run == nil {
		t.Fatal("default command runner is nil")
	}

	client = NewClient(WithTimeout(250 * time.Millisecond))
	if client.timeout != 250*time.Millisecond {
		t.Errorf("overridden timeout = %v, want 250ms", client.timeout)
	}
	if NewClient(WithTimeout(0)).timeout != DefaultTimeout {
		t.Errorf("nonpositive timeout was not normalized")
	}
}

func TestClientCommandFailure(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	wantErr := errors.New("runner failed")
	runner := func(_ context.Context, _ string, _ ...string) error { return wantErr }
	client := NewClient(WithCommandRunner(runner), WithTimeout(time.Second))

	_, session, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
	if session != nil {
		t.Fatal("session is non-nil after command failure")
	}
	if !errors.Is(err, ErrPluginUnavailable) {
		t.Fatalf("error = %v, want ErrPluginUnavailable", err)
	}
	if strings.Contains(err.Error(), runtimeDir) {
		t.Errorf("error exposes runtime directory: %v", err)
	}
}

func TestClientParentCancellation(t *testing.T) {
	newTestRuntime(t)
	calls := make(chan struct{}, 1)
	runner := func(ctx context.Context, _ string, _ ...string) error {
		calls <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	client := NewClient(WithCommandRunner(runner))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := client.RequestPasswordWithSession(ctx, "title", "message")
		result <- err
	}()
	eventually(t, func() bool {
		select {
		case <-calls:
			cancel()
			return true
		default:
			return false
		}
	})
	select {
	case err := <-result:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("error = %v, want ErrCancelled", err)
		}
	case <-time.After(testPollDeadline):
		t.Fatal("request did not return after cancellation")
	}
}

func TestClientParentDeadline(t *testing.T) {
	newTestRuntime(t)
	runner := func(ctx context.Context, _ string, _ ...string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	client := NewClient(WithCommandRunner(runner))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := client.RequestPasswordWithSession(ctx, "title", "message")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
}

func TestClientRequestTimeout(t *testing.T) {
	newTestRuntime(t)
	client, calls := newTestClient(t, 30*time.Millisecond)
	result := make(chan error, 1)
	go func() {
		_, _, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- err
	}()
	call := waitForCommand(t, calls)
	newTestBridge(t, call)
	select {
	case err := <-result:
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("error = %v, want ErrTimeout", err)
		}
	case <-time.After(testPollDeadline):
		t.Fatal("request did not time out")
	}
}

func TestClientConfirmOnly(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan error, 1)
	go func() {
		_, _, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- err
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	commandArgs(t, call, request.Cookie)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultConfirmed})
	select {
	case err := <-result:
		if !errors.Is(err, ErrConfirmOnly) {
			t.Fatalf("error = %v, want ErrConfirmOnly", err)
		}
	case <-time.After(testPollDeadline):
		t.Fatal("confirm-only request did not return")
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestPasswordSessionSuccessfulPassword(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan struct {
		password string
		session  *PasswordSession
		err      error
	}, 1)
	go func() {
		password, session, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- struct {
			password string
			session  *PasswordSession
			err      error
		}{password, session, err}
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	commandArgs(t, call, request.Cookie)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "secret"})
	got := <-result
	if got.err != nil {
		t.Fatalf("request error = %v", got.err)
	}
	if got.password != "secret" {
		t.Errorf("password = %q, want %q", got.password, "secret")
	}
	if got.session == nil {
		t.Fatal("session is nil after successful password")
	}

	resultDone := make(chan error, 1)
	go func() { resultDone <- got.session.SendResult(true, "", false) }()
	waitForClientPendingResult(t, got.session.bridge)
	finalResult := bridge.pollResult(t)
	if finalResult != (KeyringResult{Type: MessageTypeResult, ID: bridge.cookie, Success: true}) {
		t.Errorf("final result = %#v", finalResult)
	}
	if err := <-resultDone; err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestClientRequestPasswordClosesSuccessfulSession(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan struct {
		password string
		err      error
	}, 1)
	go func() {
		password, err := client.RequestPassword(context.Background(), "title", "message")
		result <- struct {
			password string
			err      error
		}{password, err}
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "secret"})
	got := <-result
	if got.err != nil || got.password != "secret" {
		t.Fatalf("RequestPassword() = %q, %v", got.password, got.err)
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestPasswordSessionRetryThenSuccess(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan struct {
		password string
		session  *PasswordSession
		err      error
	}, 1)
	go func() {
		password, session, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- struct {
			password string
			session  *PasswordSession
			err      error
		}{password, session, err}
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "wrong"})
	got := <-result
	if got.err != nil {
		t.Fatalf("initial request error = %v", got.err)
	}

	sendDone := make(chan error, 1)
	go func() { sendDone <- got.session.SendResult(false, "invalid", true) }()
	if result := bridge.pollResult(t); result.Error != "invalid" || result.Retry != true || result.Success {
		t.Errorf("retry result = %#v", result)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("retry SendResult() error = %v", err)
	}

	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "correct"})
	retryPassword, err := got.session.WaitForRetry(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("WaitForRetry() error = %v", err)
	}
	if retryPassword != "correct" {
		t.Errorf("retry password = %q, want %q", retryPassword, "correct")
	}
	finalDone := make(chan error, 1)
	go func() { finalDone <- got.session.SendResult(true, "", false) }()
	waitForClientPendingResult(t, got.session.bridge)
	bridge.pollResult(t)
	if err := <-finalDone; err != nil {
		t.Fatalf("final SendResult() error = %v", err)
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestPasswordSessionRetryTimeoutClosesSession(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan struct {
		session *PasswordSession
		err     error
	}, 1)
	go func() {
		_, session, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- struct {
			session *PasswordSession
			err     error
		}{session, err}
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "wrong"})
	got := <-result
	if got.err != nil {
		t.Fatalf("initial request error = %v", got.err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- got.session.SendResult(false, "invalid", true) }()
	bridge.pollResult(t)
	if err := <-sendDone; err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}
	if _, err := got.session.WaitForRetry(context.Background(), 20*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("WaitForRetry() error = %v, want ErrTimeout", err)
	}
	if err := got.session.SendResult(true, "", false); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("SendResult() after timeout = %v, want ErrSessionClosed", err)
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestPasswordSessionFinalFailureCleansUp(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan struct {
		session *PasswordSession
		err     error
	}, 1)
	go func() {
		_, session, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- struct {
			session *PasswordSession
			err     error
		}{session, err}
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "wrong"})
	got := <-result
	if got.err != nil {
		t.Fatalf("initial request error = %v", got.err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- got.session.SendResult(false, "invalid", false) }()
	waitForClientPendingResult(t, got.session.bridge)
	finalResult := bridge.pollResult(t)
	if finalResult.Success || finalResult.Retry || finalResult.Error != "invalid" {
		t.Errorf("final failure result = %#v", finalResult)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestClientCommandArgumentsDoNotExposeSecrets(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan struct {
		password string
		err      error
	}, 1)
	go func() {
		password, err := client.RequestPassword(context.Background(), "title", "message")
		result <- struct {
			password string
			err      error
		}{password, err}
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	password := "super-secret-password"
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: password})
	got := <-result
	if got.err != nil || got.password != password {
		t.Fatalf("request result = %q, %v", got.password, got.err)
	}
	joined := strings.Join(append([]string{call.name}, call.args...), " ")
	for _, secret := range []string{password, bridge.descriptor.Token, bridge.descriptor.BaseURL, descriptorPath(runtimeDir, bridge.cookie)} {
		if strings.Contains(joined, secret) {
			t.Errorf("command arguments contain secret %q: %s", secret, joined)
		}
	}
}

func TestPasswordSessionCloseIsIdempotent(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client, calls := newTestClient(t, time.Second)
	result := make(chan *PasswordSession, 1)
	go func() {
		_, session, _ := client.RequestPasswordWithSession(context.Background(), "title", "message")
		result <- session
	}()
	call := waitForCommand(t, calls)
	bridge := newTestBridge(t, call)
	request := bridge.getRequest(t)
	bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "secret"})
	session := <-result
	if session == nil {
		t.Fatal("session is nil")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := session.SendResult(true, "", false); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("SendResult() after Close() = %v, want ErrSessionClosed", err)
	}
	assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
}

func TestPasswordSessionProtocolAndCookieErrorsClose(t *testing.T) {
	for _, test := range []struct {
		name     string
		response func(*testBridge) KeyringResponse
		want     error
	}{
		{
			name: "cookie",
			response: func(b *testBridge) KeyringResponse {
				return KeyringResponse{Type: MessageTypeResponse, ID: strings.Repeat("a", 32), Result: ResultOK, Password: "secret"}
			},
			want: ErrCookieMismatch,
		},
		{
			name: "protocol",
			response: func(b *testBridge) KeyringResponse {
				return KeyringResponse{Type: MessageTypeRequest, ID: b.cookie, Result: ResultOK, Password: "secret"}
			},
			want: ErrProtocolError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtimeDir := newTestRuntime(t)
			client, calls := newTestClient(t, time.Second)
			result := make(chan struct {
				session *PasswordSession
				err     error
			}, 1)
			go func() {
				_, session, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
				result <- struct {
					session *PasswordSession
					err     error
				}{session, err}
			}()
			call := waitForCommand(t, calls)
			bridge := newTestBridge(t, call)
			request := bridge.getRequest(t)
			bridge.postResponse(t, KeyringResponse{Type: MessageTypeResponse, ID: request.Cookie, Result: ResultOK, Password: "secret"})
			got := <-result
			if got.err != nil || got.session == nil {
				t.Fatalf("initial request = session %v, error %v", got.session, got.err)
			}
			response := test.response(bridge)
			if test.name == "cookie" && response.ID == request.Cookie {
				t.Fatal("test response accidentally matches request cookie")
			}
			reserveBridgeResponse(got.session.bridge, response)
			if _, err := got.session.WaitForRetry(context.Background(), time.Second); !errors.Is(err, test.want) {
				t.Fatalf("WaitForRetry() error = %v, want %v", err, test.want)
			}
			assertDescriptorRemoved(t, runtimeDir, bridge.cookie)
		})
	}
}

func TestClientErrorFormattingDoesNotExposeBridgeDetails(t *testing.T) {
	runtimeDir := newTestRuntime(t)
	client := NewClient(WithCommandRunner(func(context.Context, string, ...string) error {
		return fmt.Errorf("runner error")
	}))
	_, _, err := client.RequestPasswordWithSession(context.Background(), "title", "message")
	if err == nil || !errors.Is(err, ErrPluginUnavailable) {
		t.Fatalf("error = %v, want wrapped ErrPluginUnavailable", err)
	}
	if strings.Contains(err.Error(), runtimeDir) || strings.Contains(err.Error(), "noctalia-") {
		t.Errorf("error exposes bridge details: %v", err)
	}
}

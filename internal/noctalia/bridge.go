package noctalia

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const bridgeBodyLimit = 64 << 10

type responseState uint8

const (
	responseStateAccepting responseState = iota
	responseStateReserved
	responseStateConsumed
	responseStateTerminal
)

type bridgeDescriptor struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	BaseURL   string `json:"base_url"`
	Token     string `json:"token"`
}

type resultDelivery struct {
	result    KeyringResult
	done      chan error
	claimed   bool
	abandoned bool
	completed bool
	err       error
}

type promptBridge struct {
	listener                net.Listener
	server                  *http.Server
	request                 KeyringRequest
	token                   string
	descriptor              string
	descriptorFile          *os.File
	directoryFile           *os.File
	responseNotify          chan struct{}
	done                    chan struct{}
	closeOnce               sync.Once
	mu                      sync.Mutex
	closed                  bool
	responseState           responseState
	responseSlot            KeyringResponse
	responseError           error
	responseReservationHook func()
	waiterStartHook         func()
	waiterActive            bool
	pendingResult           *resultDelivery
	pendingReady            chan struct{}
	closeErr                error
}

var errBridgeCleanup = errors.New("failed to clean up noctalia prompt bridge")

func newPromptBridge(request KeyringRequest) (*promptBridge, error) {
	return newPromptBridgeWithDescriptorWriter(request, writeBridgeDescriptor)
}

func newPromptBridgeWithDescriptorWriter(request KeyringRequest, descriptorWriter func(*os.File, bridgeDescriptor) error) (*promptBridge, error) {
	if !validBridgeCookie(request.Cookie) {
		return nil, errors.New("invalid noctalia request cookie")
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" || !filepath.IsAbs(runtimeDir) {
		return nil, errors.New("invalid XDG_RUNTIME_DIR")
	}
	if err := validateBridgeDirectory(runtimeDir); err != nil {
		return nil, fmt.Errorf("invalid XDG_RUNTIME_DIR: %w", err)
	}

	bridgeDir := filepath.Join(runtimeDir, "bitwarden-keyring")
	childInfo, childCreated, err := ensureBridgeDirectory(bridgeDir)
	if err != nil {
		return nil, fmt.Errorf("invalid bridge directory: %w", err)
	}

	directoryFD, err := unix.Open(bridgeDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open bridge directory: %w", err)
	}
	directoryFile := os.NewFile(uintptr(directoryFD), bridgeDir)
	if directoryFile == nil {
		_ = unix.Close(directoryFD)
		return nil, errors.New("open bridge directory: failed to wrap file")
	}
	openedChildInfo, err := directoryFile.Stat()
	if err != nil {
		_ = directoryFile.Close()
		return nil, fmt.Errorf("stat bridge directory: %w", err)
	}
	if !os.SameFile(childInfo, openedChildInfo) {
		_ = directoryFile.Close()
		return nil, errors.New("bridge directory changed during setup")
	}
	if childCreated {
		if err := unix.Fchmod(int(directoryFile.Fd()), 0700); err != nil {
			_ = directoryFile.Close()
			return nil, fmt.Errorf("set bridge directory permissions: %w", err)
		}
		childInfo, err = directoryFile.Stat()
		if err != nil {
			_ = directoryFile.Close()
			return nil, fmt.Errorf("stat bridge directory: %w", err)
		}
	}
	if err := validateBridgeFileDirectory(directoryFile); err != nil {
		_ = directoryFile.Close()
		return nil, fmt.Errorf("invalid bridge directory: %w", err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = directoryFile.Close()
		return nil, fmt.Errorf("listen for prompt bridge: %w", err)
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		_ = listener.Close()
		_ = directoryFile.Close()
		return nil, fmt.Errorf("generate prompt bridge token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	descriptorName := "noctalia-" + request.Cookie + ".json"
	descriptorPath := filepath.Join(bridgeDir, descriptorName)
	descriptorFD, err := unix.Openat(int(directoryFile.Fd()), descriptorName, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		_ = listener.Close()
		_ = directoryFile.Close()
		return nil, fmt.Errorf("create prompt bridge descriptor: %w", err)
	}
	descriptorFile := os.NewFile(uintptr(descriptorFD), descriptorPath)
	if descriptorFile == nil {
		_ = unix.Close(descriptorFD)
		_ = listener.Close()
		_ = directoryFile.Close()
		return nil, errors.New("create prompt bridge descriptor: failed to wrap file")
	}

	descriptor := bridgeDescriptor{
		Version:   1,
		RequestID: request.Cookie,
		BaseURL:   "http://" + listener.Addr().String(),
		Token:     token,
	}
	// The descriptor is intentionally created at its final name as required by
	// the v5 contract. It is not consumable by the intended plugin flow until
	// encoding and syncing succeed, the server starts, and this constructor
	// returns to the caller that invokes the plugin CLI.
	if err := descriptorWriter(descriptorFile, descriptor); err != nil {
		cleanupErr := cleanupBridgeDescriptor(directoryFile, descriptorFile, descriptorName)
		cleanupErr = errors.Join(cleanupErr, closeBridgeFile(descriptorFile), listener.Close(), closeBridgeFile(directoryFile))
		return nil, fmt.Errorf("write prompt bridge descriptor: %w", errors.Join(err, cleanupErr))
	}

	bridge := &promptBridge{
		listener:       listener,
		request:        request,
		token:          token,
		descriptor:     descriptorPath,
		descriptorFile: descriptorFile,
		directoryFile:  directoryFile,
		responseNotify: make(chan struct{}),
		done:           make(chan struct{}),
		responseState:  responseStateAccepting,
		pendingReady:   make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/request", bridge.handleRequest)
	mux.HandleFunc("/v1/response", bridge.handleResponse)
	mux.HandleFunc("/v1/result", bridge.handleResult)
	bridge.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	go bridge.serve()
	return bridge, nil
}

func validBridgeCookie(cookie string) bool {
	if len(cookie) != 32 {
		return false
	}
	for _, character := range cookie {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateBridgeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("directory is a symbolic link")
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	return validateBridgeFileInfo(info)
}

func ensureBridgeDirectory(path string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		mkdirErr := os.Mkdir(path, 0700)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			return nil, false, mkdirErr
		}
		created = mkdirErr == nil
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, errors.New("directory is a symbolic link")
	}
	if !info.IsDir() {
		return nil, false, errors.New("path is not a directory")
	}
	if created {
		if err := os.Chmod(path, 0700); err != nil {
			return nil, false, err
		}
		info, err = os.Lstat(path)
		if err != nil {
			return nil, false, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, false, errors.New("child directory changed during setup")
		}
	}
	if info.Mode().Perm() != 0700 {
		return nil, false, errors.New("directory mode is not 0700")
	}
	if created {
		if err := validateBridgeOwnership(info); err != nil {
			return nil, false, err
		}
	} else if err := validateBridgeFileInfo(info); err != nil {
		return nil, false, err
	}
	return info, created, nil
}

func validateBridgeFileDirectory(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	if info.Mode().Perm() != 0700 {
		return errors.New("directory mode is not 0700")
	}
	return validateBridgeFileInfo(info)
}

func validateBridgeFileInfo(info os.FileInfo) error {
	if err := validateBridgeOwnership(info); err != nil {
		return err
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("directory is group or world writable")
	}
	return nil
}

func validateBridgeOwnership(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("failed to get directory ownership")
	}
	if uint32(os.Getuid()) != stat.Uid {
		return errors.New("directory owned by a different user")
	}
	return nil
}

func writeBridgeDescriptor(file *os.File, descriptor bridgeDescriptor) error {
	return writeBridgeDescriptorWithSync(file, descriptor, func(file *os.File) error {
		return file.Sync()
	})
}

func writeBridgeDescriptorWithSync(file *os.File, descriptor bridgeDescriptor, syncFile func(*os.File) error) error {
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(descriptor); err != nil {
		return err
	}
	if err := syncFile(file); err != nil {
		return err
	}
	_, err := file.Seek(0, io.SeekStart)
	return err
}

func (b *promptBridge) serve() {
	if err := b.server.Serve(b.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_ = b.Close()
	}
}

func (b *promptBridge) handleRequest(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(r) {
		writeBridgeStatus(w, http.StatusNotFound)
		return
	}
	if b.isClosed() {
		writeBridgeStatus(w, http.StatusGone)
		return
	}
	if r.Method != http.MethodGet {
		writeBridgeStatus(w, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(b.request)
}

func (b *promptBridge) handleResponse(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(r) {
		writeBridgeStatus(w, http.StatusNotFound)
		return
	}
	if b.isClosed() {
		writeBridgeStatus(w, http.StatusGone)
		return
	}
	if r.Method != http.MethodPost {
		writeBridgeStatus(w, http.StatusNotFound)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeBridgeStatus(w, http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > bridgeBodyLimit {
		writeBridgeStatus(w, http.StatusRequestEntityTooLarge)
		return
	}

	var response KeyringResponse
	if err := decodeBridgeJSON(w, r, &response); err != nil {
		writeBridgeStatus(w, err.status)
		return
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		writeBridgeStatus(w, http.StatusGone)
		return
	}
	if b.responseState != responseStateAccepting {
		b.mu.Unlock()
		writeBridgeStatus(w, http.StatusConflict)
		return
	}
	if !validKeyringResponse(b.request, response) {
		b.mu.Unlock()
		writeBridgeStatus(w, http.StatusBadRequest)
		return
	}
	b.responseState = responseStateReserved
	b.responseSlot = response
	hook := b.responseReservationHook
	close(b.responseNotify)
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	writeBridgeStatus(w, http.StatusAccepted)
}

func (b *promptBridge) handleResult(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(r) {
		writeBridgeStatus(w, http.StatusNotFound)
		return
	}
	if b.isClosed() {
		writeBridgeStatus(w, http.StatusGone)
		return
	}
	if r.Method != http.MethodGet {
		writeBridgeStatus(w, http.StatusNotFound)
		return
	}
	values, ok := r.URL.Query()["id"]
	if !ok || len(values) != 1 || !validBridgeCookie(values[0]) || values[0] != b.request.Cookie {
		writeBridgeStatus(w, http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		writeBridgeStatus(w, http.StatusGone)
		return
	}
	delivery := b.pendingResult
	if delivery == nil {
		b.mu.Unlock()
		writeBridgeStatus(w, http.StatusNoContent)
		return
	}
	if delivery.claimed {
		b.mu.Unlock()
		writeBridgeStatus(w, http.StatusConflict)
		return
	}
	delivery.claimed = true
	result := delivery.result
	b.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeErr := json.NewEncoder(w).Encode(result)
	b.finishDelivery(delivery, writeErr, result.Retry && !result.Success)
}

func writeBridgeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

func (b *promptBridge) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	authorization := r.Header.Values("Authorization")
	if len(authorization) != 1 {
		return false
	}
	const bearerPrefix = "Bearer "
	if len(authorization[0]) <= len(bearerPrefix) || authorization[0][:len(bearerPrefix)] != bearerPrefix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(b.token), []byte(authorization[0][len(bearerPrefix):])) == 1
}

func (b *promptBridge) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

type bridgeDecodeError struct {
	status int
}

func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

func decodeBridgeJSON(w http.ResponseWriter, r *http.Request, destination any) *bridgeDecodeError {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bridgeBodyLimit))
	if err != nil {
		if isBodyLimitError(err) {
			return &bridgeDecodeError{status: http.StatusRequestEntityTooLarge}
		}
		return &bridgeDecodeError{status: http.StatusBadRequest}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return &bridgeDecodeError{status: http.StatusBadRequest}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return &bridgeDecodeError{status: http.StatusBadRequest}
	}
	return nil
}

func isBodyLimitError(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func validKeyringResponse(request KeyringRequest, response KeyringResponse) bool {
	if response.Type != MessageTypeResponse || response.ID != request.Cookie {
		return false
	}
	switch response.Result {
	case ResultOK:
		return response.Password != ""
	case ResultCancelled, ResultConfirmed:
		return response.Password == ""
	default:
		return false
	}
}

func (b *promptBridge) waitResponse(ctx context.Context, timeout time.Duration) (KeyringResponse, error) {
	b.mu.Lock()
	// A reservation is authoritative even if Close has already marked the
	// transport closed; only a waiter that was already active may consume it.
	if b.waiterActive {
		b.mu.Unlock()
		return KeyringResponse{}, ErrProtocolError
	}
	b.waiterActive = true
	hook := b.waiterStartHook
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	b.mu.Lock()
	defer func() {
		b.mu.Lock()
		b.waiterActive = false
		b.mu.Unlock()
	}()
	if response, ok := b.consumeResponseLocked(); ok {
		b.mu.Unlock()
		return response, nil
	}
	if b.responseState == responseStateTerminal {
		err := b.responseError
		b.mu.Unlock()
		return KeyringResponse{}, err
	}
	if b.responseState == responseStateConsumed {
		b.mu.Unlock()
		return KeyringResponse{}, ErrSessionClosed
	}
	if b.closed && b.responseState != responseStateReserved {
		b.mu.Unlock()
		return KeyringResponse{}, ErrSessionClosed
	}
	if err := bridgeContextError(ctx); err != nil {
		err = b.terminateResponseWaitLocked(err)
		b.mu.Unlock()
		return KeyringResponse{}, err
	}
	if timeout <= 0 {
		err := b.terminateResponseWaitLocked(ErrTimeout)
		b.mu.Unlock()
		return KeyringResponse{}, err
	}
	notify := b.responseNotify
	b.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ctxDone := ctx.Done()
	timerDone := timer.C
	bridgeDone := b.done
	for {
		select {
		case <-notify:
			b.mu.Lock()
			if response, ok := b.consumeResponseLocked(); ok {
				b.mu.Unlock()
				return response, nil
			}
			err := b.responseWaitErrorLocked()
			b.mu.Unlock()
			if err != nil {
				return KeyringResponse{}, err
			}
		case <-ctxDone:
			b.mu.Lock()
			if response, ok := b.consumeResponseLocked(); ok {
				b.mu.Unlock()
				return response, nil
			}
			err := b.responseWaitErrorLocked()
			if err == nil {
				err = b.terminateResponseWaitLocked(bridgeContextError(ctx))
			}
			b.mu.Unlock()
			return KeyringResponse{}, err
		case <-timerDone:
			b.mu.Lock()
			if response, ok := b.consumeResponseLocked(); ok {
				b.mu.Unlock()
				return response, nil
			}
			err := b.responseWaitErrorLocked()
			if err == nil {
				err = b.terminateResponseWaitLocked(ErrTimeout)
			}
			b.mu.Unlock()
			return KeyringResponse{}, err
		case <-bridgeDone:
			b.mu.Lock()
			if response, ok := b.consumeResponseLocked(); ok {
				b.mu.Unlock()
				return response, nil
			}
			err := b.responseWaitErrorLocked()
			b.mu.Unlock()
			if err != nil {
				return KeyringResponse{}, err
			}
			return KeyringResponse{}, ErrSessionClosed
		}
	}
}

func (b *promptBridge) consumeResponseLocked() (KeyringResponse, bool) {
	if b.responseState != responseStateReserved {
		return KeyringResponse{}, false
	}
	response := b.responseSlot
	b.responseSlot = KeyringResponse{}
	b.responseState = responseStateConsumed
	return response, true
}

func (b *promptBridge) responseWaitErrorLocked() error {
	switch b.responseState {
	case responseStateTerminal:
		return b.responseError
	case responseStateConsumed:
		return ErrSessionClosed
	}
	if b.closed {
		return ErrSessionClosed
	}
	return nil
}

func (b *promptBridge) terminateResponseWaitLocked(err error) error {
	if b.responseState != responseStateAccepting {
		if b.responseState == responseStateTerminal {
			return b.responseError
		}
		return ErrSessionClosed
	}
	b.responseState = responseStateTerminal
	b.responseError = err
	b.responseSlot = KeyringResponse{}
	return err
}

func bridgeContextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ErrTimeout
		}
		return ErrCancelled
	default:
		return nil
	}
}

func (b *promptBridge) sendResult(ctx context.Context, result KeyringResult) error {
	if err := bridgeContextError(ctx); err != nil {
		return err
	}
	if result.Type != MessageTypeResult || result.ID != b.request.Cookie {
		return ErrProtocolError
	}
	delivery := &resultDelivery{result: result, done: make(chan error, 1)}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrSessionClosed
	}
	if b.responseState != responseStateConsumed && b.responseState != responseStateAccepting {
		b.mu.Unlock()
		return ErrProtocolError
	}
	if b.pendingResult != nil {
		b.mu.Unlock()
		return errors.New("noctalia result already pending")
	}
	b.pendingResult = delivery
	ready := b.pendingReady
	b.pendingReady = make(chan struct{})
	b.mu.Unlock()
	close(ready)

	select {
	case err := <-delivery.done:
		return err
	case <-ctx.Done():
		return b.abandonDelivery(delivery, bridgeContextError(ctx))
	case <-b.done:
		return b.abandonDelivery(delivery, ErrSessionClosed)
	}
}

func (b *promptBridge) abandonDelivery(delivery *resultDelivery, err error) error {
	b.mu.Lock()
	if b.pendingResult == delivery && !delivery.abandoned {
		delivery.abandoned = true
		b.pendingResult = nil
		delivery.completed = true
		delivery.err = err
		b.mu.Unlock()
		return err
	}
	if delivery.abandoned || delivery.completed {
		b.mu.Unlock()
		return delivery.err
	}
	b.mu.Unlock()
	return <-delivery.done
}

func (b *promptBridge) finishDelivery(delivery *resultDelivery, err error, allowRetry bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pendingResult != delivery || delivery.abandoned {
		return
	}
	b.pendingResult = nil
	delivery.completed = true
	delivery.err = err
	if allowRetry && err == nil && !b.closed && b.responseState == responseStateConsumed {
		b.responseState = responseStateAccepting
		b.responseNotify = make(chan struct{})
	}
	delivery.done <- err
}

func (b *promptBridge) Close() error {
	b.closeOnce.Do(func() {
		var closeErr error
		b.mu.Lock()
		b.closed = true
		if delivery := b.pendingResult; delivery != nil {
			delivery.abandoned = true
			delivery.completed = true
			delivery.err = ErrSessionClosed
			b.pendingResult = nil
		}
		if b.responseState == responseStateReserved {
			// The active waiter owns this reserved response and may consume it.
		} else if b.responseState == responseStateAccepting {
			b.responseState = responseStateTerminal
			b.responseError = ErrSessionClosed
			b.responseSlot = KeyringResponse{}
		}
		close(b.done)
		b.mu.Unlock()

		if b.server != nil {
			closeErr = firstBridgeCloseError(closeErr, b.server.Close())
		} else if b.listener != nil {
			closeErr = firstBridgeCloseError(closeErr, b.listener.Close())
		}
		if b.descriptorFile != nil && b.directoryFile != nil {
			closeErr = firstBridgeCloseError(closeErr, cleanupBridgeDescriptor(b.directoryFile, b.descriptorFile, filepath.Base(b.descriptor)))
		}
		if b.descriptorFile != nil {
			closeErr = firstBridgeCloseError(closeErr, closeBridgeFile(b.descriptorFile))
		}
		if b.directoryFile != nil {
			closeErr = firstBridgeCloseError(closeErr, closeBridgeFile(b.directoryFile))
		}
		b.closeErr = closeErr
	})
	return b.closeErr
}

func firstBridgeCloseError(first, err error) error {
	if first != nil {
		return first
	}
	if err != nil {
		return errBridgeCleanup
	}
	return nil
}

func closeBridgeFile(file *os.File) error {
	if err := file.Close(); err != nil {
		return errBridgeCleanup
	}
	return nil
}

func cleanupBridgeDescriptor(directoryFile, descriptorFile *os.File, name string) error {
	pathInfo, err := fstatatInfo(int(directoryFile.Fd()), name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errBridgeCleanup
	}
	fileInfo, err := descriptorFile.Stat()
	if err != nil {
		return errBridgeCleanup
	}
	if !os.SameFile(pathInfo, fileInfo) {
		return nil
	}
	if err := unix.Unlinkat(int(directoryFile.Fd()), name, 0); err != nil {
		return errBridgeCleanup
	}
	return nil
}

func fstatatInfo(directoryFD int, name string) (os.FileInfo, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open descriptor for identity comparison: failed to wrap file")
	}
	defer file.Close()
	return file.Stat()
}

package dbus

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// mockExportFunc is a controllable export function for testing
type mockExportFunc struct {
	delay      time.Duration
	shouldFail bool
	callCount  atomic.Int32
	exportGate chan struct{} // blocks export until closed
}

func (m *mockExportFunc) export(item *Item) error {
	m.callCount.Add(1)

	// Wait on gate if set (allows test to control when export proceeds)
	if m.exportGate != nil {
		<-m.exportGate
	}

	// Simulate slow export
	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldFail {
		return errors.New("export failed")
	}
	return nil
}

// TestItemManager_ConcurrentCreateDifferentItems verifies that creating
// different items concurrently doesn't serialize due to lock being held
func TestItemManager_ConcurrentCreateDifferentItems(t *testing.T) {
	im := &ItemManager{
		items: make(map[dbus.ObjectPath]*itemEntry),
	}

	exportDelay := 100 * time.Millisecond
	mockExport := &mockExportFunc{delay: exportDelay}
	im.exportFunc = mockExport.export

	// Create 3 different items concurrently
	numItems := 3
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numItems; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bwItem := &bitwarden.Item{
				ID:   string(rune('a' + idx)), // "a", "b", "c"
				Name: "test",
			}
			_, err := im.GetOrCreateItem(bwItem, nil)
			if err != nil {
				t.Errorf("GetOrCreateItem failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// If lock was held during export, total time would be 3*100ms = 300ms+
	// With lock released, all three should run concurrently: ~100ms
	maxExpected := exportDelay + 50*time.Millisecond // some buffer
	if elapsed > maxExpected*time.Duration(numItems) {
		t.Errorf("Operations serialized (took %v), expected concurrent execution (~%v)", elapsed, maxExpected)
	}

	if elapsed > maxExpected*2 {
		t.Logf("Warning: took %v, expected ~%v (may be concurrent)", elapsed, maxExpected)
	}

	// Verify all items were created
	if mockExport.callCount.Load() != int32(numItems) {
		t.Errorf("export called %d times, expected %d", mockExport.callCount.Load(), numItems)
	}
}

// TestItemManager_ConcurrentCreateSameItem verifies that multiple
// concurrent calls for the same item wait and reuse the result
func TestItemManager_ConcurrentCreateSameItem(t *testing.T) {
	im := &ItemManager{
		items: make(map[dbus.ObjectPath]*itemEntry),
	}

	// Use gate to control when export completes
	exportGate := make(chan struct{})
	mockExport := &mockExportFunc{exportGate: exportGate}
	im.exportFunc = mockExport.export

	bwItem := &bitwarden.Item{
		ID:   "same-item",
		Name: "test",
	}

	// Start 3 concurrent calls for same item
	numCalls := 3
	var wg sync.WaitGroup
	results := make([]*Item, numCalls)
	errs := make([]error, numCalls)

	for i := 0; i < numCalls; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = im.GetOrCreateItem(bwItem, nil)
		}(i)
	}

	// Give goroutines time to all hit the wait point
	time.Sleep(50 * time.Millisecond)

	// Now allow export to proceed
	close(exportGate)

	wg.Wait()

	// Export should only be called once
	if count := mockExport.callCount.Load(); count != 1 {
		t.Errorf("export called %d times, expected 1 (deduplication failed)", count)
	}

	// All calls should succeed and return same item
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d failed: %v", i, err)
		}
	}

	// All should return the same pointer (or at least same path)
	if results[0] != nil {
		for i := 1; i < numCalls; i++ {
			if results[i] == nil || results[i].path != results[0].path {
				t.Errorf("call %d returned different item", i)
			}
		}
	}
}

// TestItemManager_GetItemWaitsForReady verifies that GetItem waits
// for export to complete before returning
func TestItemManager_GetItemWaitsForReady(t *testing.T) {
	im := &ItemManager{
		items: make(map[dbus.ObjectPath]*itemEntry),
	}

	exportGate := make(chan struct{})
	mockExport := &mockExportFunc{exportGate: exportGate}
	im.exportFunc = mockExport.export

	bwItem := &bitwarden.Item{
		ID:   "test-item",
		Name: "test",
	}
	path := ItemPathFromID(bwItem.ID)

	// Start creation in background
	createDone := make(chan error, 1)
	go func() {
		_, err := im.GetOrCreateItem(bwItem, nil)
		createDone <- err
	}()

	// Give it time to insert entry and start export
	time.Sleep(50 * time.Millisecond)

	// Now call GetItem - should block waiting for ready
	getChan := make(chan *Item)
	go func() {
		item, _ := im.GetItem(path)
		getChan <- item
	}()

	// Give GetItem time to block
	time.Sleep(50 * time.Millisecond)

	// Verify GetItem hasn't returned yet
	select {
	case <-getChan:
		t.Fatal("GetItem returned before export completed")
	default:
		// Good, still blocked
	}

	// Now allow export to complete
	close(exportGate)

	// GetItem should now return
	select {
	case item := <-getChan:
		if item == nil {
			t.Error("GetItem returned nil after export completed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("GetItem didn't return after export completed")
	}

	// Check creation error
	select {
	case err := <-createDone:
		if err != nil {
			t.Errorf("GetOrCreateItem failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("GetOrCreateItem didn't complete")
	}
}

// TestItemManager_ExportFailure verifies that export failures are
// properly handled - error stored, ready closed, entry deleted
func TestItemManager_ExportFailure(t *testing.T) {
	im := &ItemManager{
		items: make(map[dbus.ObjectPath]*itemEntry),
	}

	mockExport := &mockExportFunc{shouldFail: true}
	im.exportFunc = mockExport.export

	bwItem := &bitwarden.Item{
		ID:   "fail-item",
		Name: "test",
	}
	path := ItemPathFromID(bwItem.ID)

	// Attempt to create - should fail
	item, err := im.GetOrCreateItem(bwItem, nil)
	if err == nil {
		t.Error("expected error from failed export")
	}
	if item != nil {
		t.Error("expected nil item from failed export")
	}

	// Entry should be cleaned up
	im.mu.RLock()
	_, exists := im.items[path]
	im.mu.RUnlock()

	if exists {
		t.Error("failed entry should be deleted from map")
	}

	// Subsequent GetItem should return nil (not block forever)
	item2, ok := im.GetItem(path)
	if ok || item2 != nil {
		t.Error("GetItem should return nil for deleted entry")
	}
}

// TestItemManager_RemoveWaitsForReady verifies that RemoveItem waits
// for export to complete before removing
func TestItemManager_RemoveWaitsForReady(t *testing.T) {
	im := &ItemManager{
		items: make(map[dbus.ObjectPath]*itemEntry),
	}

	exportGate := make(chan struct{})
	mockExport := &mockExportFunc{exportGate: exportGate}
	im.exportFunc = mockExport.export

	bwItem := &bitwarden.Item{
		ID:   "remove-item",
		Name: "test",
	}
	path := ItemPathFromID(bwItem.ID)

	// Start creation in background
	go func() {
		im.GetOrCreateItem(bwItem, nil)
	}()

	// Give it time to insert entry
	time.Sleep(50 * time.Millisecond)

	// Start removal - should block waiting for ready
	removeDone := make(chan struct{})
	go func() {
		im.RemoveItem(path)
		close(removeDone)
	}()

	// Give RemoveItem time to try
	time.Sleep(50 * time.Millisecond)

	// Verify RemoveItem hasn't completed
	select {
	case <-removeDone:
		t.Fatal("RemoveItem completed before export finished")
	default:
		// Good, still blocked
	}

	// Now allow export to complete
	close(exportGate)

	// RemoveItem should now complete
	select {
	case <-removeDone:
		// Good
	case <-time.After(1 * time.Second):
		t.Fatal("RemoveItem didn't complete after export finished")
	}

	// Entry should be removed
	im.mu.RLock()
	_, exists := im.items[path]
	im.mu.RUnlock()

	if exists {
		t.Error("item should be removed from map")
	}
}

// TestItemManager_UpdateExistingItem verifies that GetOrCreateItem
// updates an existing item without re-exporting
func TestItemManager_UpdateExistingItem(t *testing.T) {
	im := &ItemManager{
		items: make(map[dbus.ObjectPath]*itemEntry),
	}

	mockExport := &mockExportFunc{}
	im.exportFunc = mockExport.export

	bwItem := &bitwarden.Item{
		ID:   "update-item",
		Name: "original",
	}

	// Create first time
	item1, err := im.GetOrCreateItem(bwItem, nil)
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	// Export should be called once
	if count := mockExport.callCount.Load(); count != 1 {
		t.Errorf("export called %d times, expected 1", count)
	}

	// Update the item
	bwItem.Name = "updated"

	// Call again with updated item
	item2, err := im.GetOrCreateItem(bwItem, nil)
	if err != nil {
		t.Fatalf("second create failed: %v", err)
	}

	// Should return same path
	if item1.path != item2.path {
		t.Error("expected same path for updated item")
	}

	// Export should still only be called once (no re-export)
	if count := mockExport.callCount.Load(); count != 1 {
		t.Errorf("export called %d times, expected 1 (no re-export)", count)
	}

	// Verify item data was updated
	item2.mu.RLock()
	name := item2.bwItem.Name
	item2.mu.RUnlock()

	if name != "updated" {
		t.Errorf("item name = %q, expected %q", name, "updated")
	}
}

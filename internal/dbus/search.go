package dbus

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/mapping"
)

// searchAndFilterItems searches for Bitwarden items matching the given attributes,
// filters them, and returns their D-Bus object paths. This is a shared helper used
// by both Service.searchItemsInternal and Collection.SearchItems.
//
// The function:
// 1. Builds a URI from attributes for optimized search
// 2. Searches (if URI exists) or lists all items
// 3. Filters results using MatchesAttributes
// 4. Creates/retrieves D-Bus Item objects for each match
func searchAndFilterItems(
	ctx context.Context,
	bwClient *bitwarden.Client,
	itemManager *ItemManager,
	coll *Collection,
	attrs map[string]string,
) ([]dbus.ObjectPath, error) {
	if coll == nil {
		return nil, fmt.Errorf("collection is nil")
	}

	uri := mapping.BuildURIFromAttributes(attrs)

	var items []bitwarden.Item
	var err error

	if uri != "" {
		items, err = bwClient.SearchItems(ctx, uri)
	} else {
		items, err = bwClient.ListItems(ctx)
	}

	if err != nil {
		return nil, err
	}

	var results []dbus.ObjectPath
	for _, item := range items {
		if mapping.MatchesAttributes(&item, attrs) {
			itemCopy := item
			dbusItem, err := itemManager.GetOrCreateItem(&itemCopy, coll)
			if err != nil {
				continue
			}
			results = append(results, dbusItem.Path())
		}
	}

	return results, nil
}

// getLoginItemPaths lists all login-type items from Bitwarden, ensures each is
// exported as a D-Bus Item, and returns their object paths. Items that fail to
// export are silently skipped.
func getLoginItemPaths(
	ctx context.Context,
	bwClient *bitwarden.Client,
	itemManager *ItemManager,
	coll *Collection,
) ([]dbus.ObjectPath, error) {
	if coll == nil {
		return nil, fmt.Errorf("collection is nil")
	}

	items, err := bwClient.ListItems(ctx)
	if err != nil {
		return nil, err
	}

	paths := make([]dbus.ObjectPath, 0, len(items))
	for _, item := range items {
		if item.Type == bitwarden.ItemTypeLogin {
			itemCopy := item
			dbusItem, err := itemManager.GetOrCreateItem(&itemCopy, coll)
			if err != nil {
				continue // Skip items that can't be exported
			}
			paths = append(paths, dbusItem.Path())
		}
	}
	return paths, nil
}

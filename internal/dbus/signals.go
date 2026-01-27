// Package dbus provides D-Bus Secret Service API implementation
package dbus

import (
	"log"

	"github.com/godbus/dbus/v5"
)

// EmitItemCreated emits the ItemCreated signal on the collection.
// This signal is emitted when a new item is added to a collection.
func EmitItemCreated(conn *dbus.Conn, collectionPath, itemPath dbus.ObjectPath) {
	if err := conn.Emit(collectionPath, CollectionInterface+".ItemCreated", itemPath); err != nil {
		log.Printf("Failed to emit ItemCreated signal: %v", err)
	}
}

// EmitItemDeleted emits the ItemDeleted signal on the collection.
// This signal is emitted when an item is removed from a collection.
func EmitItemDeleted(conn *dbus.Conn, collectionPath, itemPath dbus.ObjectPath) {
	if err := conn.Emit(collectionPath, CollectionInterface+".ItemDeleted", itemPath); err != nil {
		log.Printf("Failed to emit ItemDeleted signal: %v", err)
	}
}

// EmitItemChanged emits the ItemChanged signal on the collection.
// This signal is emitted when an item's secret or attributes are modified.
func EmitItemChanged(conn *dbus.Conn, collectionPath, itemPath dbus.ObjectPath) {
	if err := conn.Emit(collectionPath, CollectionInterface+".ItemChanged", itemPath); err != nil {
		log.Printf("Failed to emit ItemChanged signal: %v", err)
	}
}

// EmitCollectionCreated emits the CollectionCreated signal on the service.
// This signal is emitted when a new collection is added to the service.
func EmitCollectionCreated(conn *dbus.Conn, collectionPath dbus.ObjectPath) {
	if err := conn.Emit(ServicePath, ServiceInterface+".CollectionCreated", collectionPath); err != nil {
		log.Printf("Failed to emit CollectionCreated signal: %v", err)
	}
}

// EmitCollectionDeleted emits the CollectionDeleted signal on the service.
// This signal is emitted when a collection is removed from the service.
func EmitCollectionDeleted(conn *dbus.Conn, collectionPath dbus.ObjectPath) {
	if err := conn.Emit(ServicePath, ServiceInterface+".CollectionDeleted", collectionPath); err != nil {
		log.Printf("Failed to emit CollectionDeleted signal: %v", err)
	}
}

// EmitCollectionChanged emits the CollectionChanged signal on the service.
// This signal is emitted when a collection's properties are modified.
func EmitCollectionChanged(conn *dbus.Conn, collectionPath dbus.ObjectPath) {
	if err := conn.Emit(ServicePath, ServiceInterface+".CollectionChanged", collectionPath); err != nil {
		log.Printf("Failed to emit CollectionChanged signal: %v", err)
	}
}

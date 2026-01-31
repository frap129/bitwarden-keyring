// Package dbus provides D-Bus Secret Service API implementation
package dbus

import (
	"log"

	"github.com/godbus/dbus/v5"
)

// emit emits a D-Bus signal with error logging.
func emit(conn *dbus.Conn, path dbus.ObjectPath, signalName string, args ...interface{}) {
	if err := conn.Emit(path, signalName, args...); err != nil {
		log.Printf("Failed to emit %s signal: %v", signalName, err)
	}
}

// EmitItemCreated emits the ItemCreated signal on the collection.
// This signal is emitted when a new item is added to a collection.
func EmitItemCreated(conn *dbus.Conn, collectionPath, itemPath dbus.ObjectPath) {
	emit(conn, collectionPath, CollectionInterface+".ItemCreated", itemPath)
}

// EmitItemDeleted emits the ItemDeleted signal on the collection.
// This signal is emitted when an item is removed from a collection.
func EmitItemDeleted(conn *dbus.Conn, collectionPath, itemPath dbus.ObjectPath) {
	emit(conn, collectionPath, CollectionInterface+".ItemDeleted", itemPath)
}

// EmitItemChanged emits the ItemChanged signal on the collection.
// This signal is emitted when an item's secret or attributes are modified.
func EmitItemChanged(conn *dbus.Conn, collectionPath, itemPath dbus.ObjectPath) {
	emit(conn, collectionPath, CollectionInterface+".ItemChanged", itemPath)
}

// EmitCollectionCreated emits the CollectionCreated signal on the service.
// This signal is emitted when a new collection is added to the service.
func EmitCollectionCreated(conn *dbus.Conn, collectionPath dbus.ObjectPath) {
	emit(conn, ServicePath, ServiceInterface+".CollectionCreated", collectionPath)
}

// EmitCollectionDeleted emits the CollectionDeleted signal on the service.
// This signal is emitted when a collection is removed from the service.
func EmitCollectionDeleted(conn *dbus.Conn, collectionPath dbus.ObjectPath) {
	emit(conn, ServicePath, ServiceInterface+".CollectionDeleted", collectionPath)
}

// EmitCollectionChanged emits the CollectionChanged signal on the service.
// This signal is emitted when a collection's properties are modified.
func EmitCollectionChanged(conn *dbus.Conn, collectionPath dbus.ObjectPath) {
	emit(conn, ServicePath, ServiceInterface+".CollectionChanged", collectionPath)
}

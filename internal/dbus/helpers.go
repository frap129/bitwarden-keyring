package dbus

import (
	"log"

	"github.com/godbus/dbus/v5"
)

// exportDBusObject exports an object to D-Bus with the standard interface pattern.
// It exports the main interface, optionally the Properties interface, and always
// exports the Introspectable interface.
//
// Parameters:
//   - conn: the D-Bus connection
//   - obj: the object to export
//   - path: the D-Bus object path
//   - iface: the main interface name (e.g., CollectionInterface)
//   - introspectXML: the introspection XML for this object type
//   - exportProperties: whether to also export org.freedesktop.DBus.Properties
func exportDBusObject(conn *dbus.Conn, obj interface{}, path dbus.ObjectPath, iface string, introspectXML string, exportProperties bool) error {
	if err := conn.Export(obj, path, iface); err != nil {
		return err
	}

	if exportProperties {
		if err := conn.Export(obj, path, PropertiesInterface); err != nil {
			return err
		}
	}

	if err := conn.Export(introspectable(introspectXML), path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}

	return nil
}

// unexportDBusObject unexports all D-Bus interfaces for an object.
// This is the inverse of exportDBusObject and should be called when removing objects.
// Errors are logged but not returned since unexport failures are typically non-fatal.
//
// Parameters:
//   - conn: the D-Bus connection
//   - path: the D-Bus object path to unexport
//   - iface: the main interface name (e.g., CollectionInterface)
//   - hasProperties: whether the Properties interface was also exported
func unexportDBusObject(conn *dbus.Conn, path dbus.ObjectPath, iface string, hasProperties bool) {
	if err := conn.Export(nil, path, iface); err != nil {
		log.Printf("Failed to unexport %s interface from %s: %v", iface, path, err)
	}

	if hasProperties {
		if err := conn.Export(nil, path, PropertiesInterface); err != nil {
			log.Printf("Failed to unexport %s interface from %s: %v", PropertiesInterface, path, err)
		}
	}

	if err := conn.Export(nil, path, "org.freedesktop.DBus.Introspectable"); err != nil {
		log.Printf("Failed to unexport Introspectable interface from %s: %v", path, err)
	}
}

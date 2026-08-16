// Package supervisor implements the bounded systemd notification surface used
// by the native service without adding a runtime dependency.
package supervisor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

const maximumNotifySocketLength = 107

// NotifyReady tells a supervising systemd service that startup recovery and
// all startup gates completed. It is a no-op outside a notify-aware service.
func NotifyReady() error {
	return notify("READY=1\nSTATUS=AcmeMux is ready")
}

// NotifyStopping makes graceful shutdown visible to systemd when available.
func NotifyStopping() error {
	return notify("STOPPING=1\nSTATUS=AcmeMux is stopping")
}

func notify(message string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if len(path) > maximumNotifySocketLength {
		return errors.New("systemd notify socket path is too long")
	}
	switch path[0] {
	case '/':
	case '@':
		path = "\x00" + path[1:]
	default:
		return errors.New("systemd notify socket must be absolute or abstract")
	}
	if strings.ContainsRune(message, '\x00') || message == "" {
		return errors.New("systemd notification is invalid")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connect to systemd notify socket: %w", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(message)); err != nil {
		return fmt.Errorf("send systemd notification: %w", err)
	}
	return nil
}

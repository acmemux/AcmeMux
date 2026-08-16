package supervisor

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotifyReadyIsOptional(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := NotifyReady(); err != nil {
		t.Fatalf("NotifyReady() error = %v", err)
	}
}

func TestNotifyReadySendsBoundedSystemdDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	address := &net.UnixAddr{Name: path, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)

	if err := NotifyReady(); err != nil {
		t.Fatalf("NotifyReady() error = %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message := string(buffer[:count])
	if !strings.Contains(message, "READY=1") || !strings.Contains(message, "STATUS=AcmeMux is ready") {
		t.Fatalf("notification = %q", message)
	}
}

func TestNotifyReadyRejectsUntrustedSocketValues(t *testing.T) {
	for _, value := range []string{"relative.sock", strings.Repeat("/", maximumNotifySocketLength+1)} {
		t.Run(value[:min(len(value), 16)], func(t *testing.T) {
			t.Setenv("NOTIFY_SOCKET", value)
			if err := NotifyReady(); err == nil {
				t.Fatalf("NotifyReady() accepted %q", value)
			}
		})
	}
}

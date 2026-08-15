package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var forcedVersion = "5.3.1"

func main() {
	mode := filepath.Base(os.Args[0])
	if mode != "retained" && (len(os.Args) != 2 || os.Args[1] != "--version") {
		fmt.Fprint(os.Stderr, "unexpected argv")
		os.Exit(70)
	}

	switch mode {
	case "release":
		validateContext()
		fmt.Printf("lego version %s linux/%s\n", forcedVersion, runtime.GOARCH)
	case "revision":
		fmt.Printf("lego version 2a58c3522708e4c7393a67be691bd0c3a16d8441 linux/%s\n", runtime.GOARCH)
	case "stderr":
		fmt.Fprint(os.Stderr, "unexpected diagnostic")
		fmt.Printf("lego version %s linux/%s\n", forcedVersion, runtime.GOARCH)
	case "nonzero":
		os.Exit(9)
	case "malformed":
		fmt.Println("not lego")
	case "stdout-oversized":
		fmt.Print(strings.Repeat("x", 1000))
	case "stderr-oversized":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 1000))
	case "timeout":
		time.Sleep(10 * time.Second)
	case "darwin":
		fmt.Printf("lego version %s darwin/%s\n", forcedVersion, runtime.GOARCH)
	case "other-arch":
		architecture := "arm64"
		if runtime.GOARCH == "arm64" {
			architecture = "amd64"
		}
		fmt.Printf("lego version %s linux/%s\n", forcedVersion, architecture)
	case "slow-release":
		marker := filepath.Join(filepath.Dir(os.Args[0]), "started")
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			os.Exit(73)
		}
		time.Sleep(200 * time.Millisecond)
		fmt.Printf("lego version %s linux/%s\n", forcedVersion, runtime.GOARCH)
	case "retained":
		if len(os.Args) == 2 && os.Args[1] == "--version" {
			fmt.Printf("lego version %s linux/%s\n", forcedVersion, runtime.GOARCH)
			return
		}
		if len(os.Args) == 2 {
			fmt.Printf("retained:%s\n", os.Args[1])
			return
		}
		os.Exit(70)
	default:
		os.Exit(74)
	}
}

func validateContext() {
	workingDirectory, err := os.Getwd()
	if err != nil || len(os.Args) != 2 || os.Args[1] != "--version" || workingDirectory != "/" || os.Getenv("LANG") != "C" || os.Getenv("LC_ALL") != "C" || os.Getenv("TZ") != "UTC" || os.Getenv("ACMEMUX_RUNTIME_PROBE_LEAK") != "" {
		fmt.Fprint(os.Stderr, "unexpected process context")
		os.Exit(71)
	}
}

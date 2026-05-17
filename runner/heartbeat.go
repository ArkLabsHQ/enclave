package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/vsock"
)

func serveHeartbeat(ctx context.Context) error {
	l, err := vsock.Listen(heartbeatPort, nil)
	if err != nil {
		return fmt.Errorf("vsock listen :%d: %w", heartbeatPort, err)
	}
	defer func() { _ = l.Close() }()

	log.Printf("heartbeat: listening on vsock port %d", heartbeatPort)

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("heartbeat: accept: %v", err)
			continue
		}
		go handleHeartbeatConn(conn)
	}
}

func handleHeartbeatConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	if _, err := conn.Write(buf[:n]); err != nil {
		log.Printf("heartbeat: write: %v", err)
		return
	}
	log.Printf("heartbeat: OK (echoed %02x)", buf[0])
}

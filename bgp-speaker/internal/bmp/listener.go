package bmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

type Handler interface {
	OnConnect()
	OnDisconnect()
	HandleMessage(*gobmp.BMPMessage)
}

type Listener struct {
	handler Handler
}

func NewListener(h Handler) *Listener {
	return &Listener{handler: h}
}

// Serve runs an accept loop on ln until ctx is cancelled or ln is closed.
// Each accepted conn is dispatched to HandleConn in its own goroutine.
func (l *Listener) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go func(c net.Conn) { _ = l.HandleConn(c) }(c)
	}
}

// HandleConn reads BMP messages from conn until EOF or error, dispatching
// each parsed message to the handler. OnConnect is called at start,
// OnDisconnect is called exactly once before return.
func (l *Listener) HandleConn(conn io.ReadCloser) error {
	l.handler.OnConnect()
	defer l.handler.OnDisconnect()
	defer func() { _ = conn.Close() }()

	for {
		hdr := make([]byte, gobmp.BMP_HEADER_SIZE)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return fmt.Errorf("read header: %w", err)
		}
		length := binary.BigEndian.Uint32(hdr[1:5])
		if length < uint32(gobmp.BMP_HEADER_SIZE) {
			return fmt.Errorf("invalid bmp length %d", length)
		}
		rest := make([]byte, length-uint32(gobmp.BMP_HEADER_SIZE))
		if _, err := io.ReadFull(conn, rest); err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		full := append(hdr, rest...)
		msg, err := gobmp.ParseBMPMessage(full)
		if err != nil {
			return fmt.Errorf("parse bmp: %w", err)
		}
		l.handler.HandleMessage(msg)
	}
}

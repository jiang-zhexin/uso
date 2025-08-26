// from https://github.com/pires/go-proxyproto/blob/main/helper/http2/http2.go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const listenerRetryBaseDelay = 5 * time.Millisecond

// Server is an HTTP server accepting both regular and proxied, both HTTP/1 and
// HTTP/2 connections.
//
// HTTP/2 is negotiated using TLS ALPN, either directly via a tls.Conn, either
// indirectly via the PROXY protocol. When the PROXY protocol is used, the
// TLS-terminating proxy in front of the server must be configured to accept
// the "h2" TLS ALPN protocol.
//
// The server is closed when the http.Server is.
type Server struct {
	h1         *http.Server  // regular HTTP/1 server
	h2         *http2.Server // HTTP/2 server
	h2Err      error         // HTTP/2 server setup error, if any
	h1Listener h1Listener    // pipe listener for the HTTP/1 server

	// The following fields are protected by the mutex
	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
}

// NewServer creates a new HTTP server.
//
// A nil h2 is equivalent to a zero http2.Server.
func NewServer(h1 *http.Server, h2 *http2.Server) *Server {
	if h2 == nil {
		h2 = new(http2.Server)
	}
	srv := &Server{
		h1:        h1,
		h2:        h2,
		h2Err:     http2.ConfigureServer(h1, h2),
		listeners: make(map[net.Listener]struct{}),
	}
	srv.h1Listener = h1Listener{newPipeListener(), srv}
	go func() {
		// proxyListener.Accept never fails
		_ = h1.Serve(srv.h1Listener)
	}()
	return srv
}

func (srv *Server) errorLog() *log.Logger {
	if srv.h1.ErrorLog != nil {
		return srv.h1.ErrorLog
	}
	return log.Default()
}

func (srv *Server) serveConn(conn *tls.Conn) error {
	// See https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
	switch proto := conn.ConnectionState().NegotiatedProtocol; proto {
	case http2.NextProtoTLS, "h2c":
		defer conn.Close()
		opts := http2.ServeConnOpts{Handler: srv.h1.Handler}
		srv.h2.ServeConn(conn, &opts)
		return nil
	case "", "http/1.0", "http/1.1":
		return srv.h1Listener.ServeConn(conn)
	default:
		conn.Close()
		return fmt.Errorf("unsupported protocol %q", proto)
	}
}

func (srv *Server) closeListeners() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.closed = true

	var err error
	for ln := range srv.listeners {
		if cerr := ln.Close(); cerr != nil {
			err = cerr
		}
	}
	return err
}

// h1Listener is used to signal back http.Server's Close and Shutdown to the
// HTTP/2 server.
type h1Listener struct {
	*pipeListener
	srv *Server
}

func (ln h1Listener) Close() error {
	// pipeListener.Close never fails
	_ = ln.pipeListener.Close()
	return ln.srv.closeListeners()
}

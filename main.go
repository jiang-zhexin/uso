package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/c2FmZQ/ech"
)

func main() {
	dohServerName := "your domain"
	dohcertFile := ".crt"
	dohKeyFile := ".key"

	publicName := "any domain"
	dnsMsgA := "public IPv4"
	dnsMsgAAAA := "public IPv6"

	cert, err := tls.LoadX509KeyPair(dohcertFile, dohKeyFile)
	if err != nil {
		log.Fatalln(err)
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName != dohServerName {
				log.Printf("Rejecting connection from %s due to blacklisted SNI: %s", clientHello.Conn.RemoteAddr(), clientHello.ServerName)
				return nil, fmt.Errorf("server name indication '%s' is not allowed", clientHello.ServerName)
			}
			return &cert, nil
		},
	}

	privKey, config, err := ech.NewConfig(114, []byte(publicName))
	if err != nil {
		log.Fatalf("NewConfig: %v", err)
	}
	privKeyBytes := privKey.Bytes()
	configList, err := ech.ConfigList([]ech.Config{config})
	if err != nil {
		log.Fatalf("ConfigList: %v", err)
	}
	log.Printf("ConfigList: %s", base64.StdEncoding.EncodeToString(configList))
	defaultDnsMsg.ECH = configList
	defaultDnsMsg.A = net.ParseIP(dnsMsgA)
	defaultDnsMsg.AAAA = net.ParseIP(dnsMsgAAAA)

	echKeys := []tls.EncryptedClientHelloKey{{
		Config:      config,
		PrivateKey:  privKeyBytes,
		SendAsRetry: true,
	}}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)
	server := NewServer(&http.Server{
		Handler: mux,
	}, nil)

	ln, err := net.Listen("tcp", "0.0.0.0:443")
	if err != nil {
		log.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	log.Printf("Accepting connections on %s", ln.Addr().String())

	for {
		serverConn, err := ln.Accept()
		if err != nil {
			log.Fatalf("ln.Accept: %v", err)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := ech.NewConn(ctx, serverConn, ech.WithKeys(echKeys))
			if err != nil {
				log.Printf("NewConn: %v", err)
				return
			}

			if conn.ECHAccepted() {
				upstream, err := net.Dial("tcp", conn.ServerName()+":443")
				if err != nil {
					log.Fatalf("dial upstream %v", err)
				}

				go func() {
					defer upstream.Close()
					io.Copy(upstream, conn)
				}()
				go func() {
					defer conn.Close()
					io.Copy(conn, upstream)
				}()

			} else {
				if conn.ServerName() != publicName {
					conn.Close()
					return
				}
				tlsConn := tls.Server(conn, tc)
				server.serveConn(tlsConn)
			}
		}()
	}
}

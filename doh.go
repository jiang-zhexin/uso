package main

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

type dnsMsg struct {
	A    net.IP
	AAAA net.IP
	ECH  []byte
}

var defaultDnsMsg = &dnsMsg{}

func (d *dnsMsg) customRecords(fqdn string, dnsType uint16) []dns.RR {

	if strings.HasSuffix(fqdn, ".google.com.") {
		return nil
	}

	switch dnsType {
	case dns.TypeA:
		return []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   d.A,
			},
		}
	case dns.TypeAAAA:
		return []dns.RR{
			&dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: d.AAAA,
			},
		}
	case dns.TypeHTTPS:
		return []dns.RR{
			&dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr:      dns.RR_Header{Name: fqdn, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
					Priority: 1,
					Target:   ".",
					Value: []dns.SVCBKeyValue{
						&dns.SVCBAlpn{
							Alpn: []string{"h2"},
						},
						&dns.SVCBECHConfig{
							ECH: d.ECH,
						},
						&dns.SVCBIPv4Hint{
							Hint: []net.IP{d.A},
						},
						&dns.SVCBIPv6Hint{
							Hint: []net.IP{d.AAAA},
						},
					},
				},
			},
		}
	default:
		return nil
	}
}

func dohHandler(w http.ResponseWriter, r *http.Request) {
	var dnsQuery []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsQueryB64 := r.URL.Query().Get("dns")
		if dnsQueryB64 == "" {
			http.Error(w, "Missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		dnsQuery, err = base64.RawURLEncoding.DecodeString(dnsQueryB64)
		if err != nil {
			http.Error(w, "Invalid base64 encoding", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
			return
		}
		dnsQuery, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(dnsQuery); err != nil {
		http.Error(w, "Failed to parse DNS query", http.StatusBadRequest)
		return
	}

	if len(reqMsg.Question) == 0 {
		http.Error(w, "Empty DNS question", http.StatusBadRequest)
		return
	}

	respMsg := new(dns.Msg)
	respMsg.SetReply(reqMsg)

	question := reqMsg.Question[0]
	log.Printf("Received query for %s, type %s", question.Name, dns.TypeToString[question.Qtype])

	respMsg.Answer = defaultDnsMsg.customRecords(question.Name, question.Qtype)

	respBytes, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		log.Printf("Error packing response: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	cert, err := loadCerts()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	certPool, err := loadCertPool()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			cname := req.TLS.PeerCertificates[0].Subject.CommonName
			io.WriteString(w, fmt.Sprintf("Hello, %s!", cname))
		} else {
			io.WriteString(w, "Hello, stranger!")
		}
	})

	srv := &http.Server{
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		Addr:         ":10443",
	}
	err = srv.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		fmt.Println(err)
		os.Exit(1)
	}
}

func loadCerts() (tls.Certificate, error) {
	certPem, err := os.ReadFile("server-tls.pem")
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPem, err := os.ReadFile("server-tls-key.pem")
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPem, keyPem)

}

func loadCertPool() (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	caCertBytes, err := os.ReadFile("ca-cert.pem")
	if err != nil {
		return nil, err
	}
	if !certPool.AppendCertsFromPEM(caCertBytes) {
		return nil, err
	}

	return certPool, nil

}

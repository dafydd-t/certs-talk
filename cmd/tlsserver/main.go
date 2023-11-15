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
	err := server()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func server() error {
	certPem, err := os.ReadFile("server-tls.pem")
	if err != nil {
		return err
	}
	keyPem, err := os.ReadFile("server-tls-key.pem")
	if err != nil {
		fmt.Println("here")
		return err
	}
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		fmt.Println("here")
		return err
	}

	certPool := x509.NewCertPool()
	caCertBytes, err := os.ReadFile("ca-cert.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if !certPool.AppendCertsFromPEM(caCertBytes) {
		fmt.Println("could not append cert from pem")
		os.Exit(1)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, TLS!\n")
	})

	srv := &http.Server{
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		Addr:         ":10443",
	}
	return srv.ListenAndServeTLS("", "")
}

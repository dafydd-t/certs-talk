package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ServerName:         "server.daf.com",
		RootCAs:            certPool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://localhost:10443")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	content, _ := io.ReadAll(resp.Body)
	s := strings.TrimSpace(string(content))

	fmt.Println(s)

}

func loadCerts() (tls.Certificate, error) {
	certPem, err := os.ReadFile("client-tls.pem")
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPem, err := os.ReadFile("client-tls-key.pem")
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

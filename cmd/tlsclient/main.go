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

	certPem, err := os.ReadFile("client-tls.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	keyPem, err := os.ReadFile("client-tls-key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
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

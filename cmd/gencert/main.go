package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {

	caCert, caSigner, err := generateCA()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = generateServerTLSCert(caCert, caSigner)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = generateClientTLSCert(caCert, caSigner)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = generateSSHCert(caSigner)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Generate a self-signed CA certificate
func generateCA() (*x509.Certificate, crypto.Signer, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DafCo"},
			CommonName:   "Dafs CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signed, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	err = writeX509ToFile(signed, "ca-cert.pem")
	if err != nil {
		return nil, nil, err
	}
	err = writeKeyToFile(privateKey, "ca-key.pem")
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(signed)
	if err != nil {
		return nil, nil, err
	}
	return caCert, privateKey, nil
}

func generateServerTLSCert(caCert *x509.Certificate, caSigner crypto.Signer) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DafCo"},
			CommonName:   "Dafs server",
		},
		DNSNames:       []string{"server.daf.com"},
		EmailAddresses: []string{"hello@daf.com"},
		IPAddresses:    []net.IP{net.ParseIP("1.2.3.4")},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, 1),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, publicKey, caSigner)
	if err != nil {
		return err
	}

	err = writeX509ToFile(certBytes, "server-tls.pem")
	if err != nil {
		return err
	}

	return writeKeyToFile(privateKey, "server-tls-key.pem")
}

func generateClientTLSCert(caCert *x509.Certificate, caSigner crypto.Signer) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DafCo"},
			CommonName:   "daf client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, 1),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, publicKey, caSigner)
	if err != nil {
		return err
	}

	err = writeX509ToFile(certBytes, "client-tls.pem")
	if err != nil {
		return err
	}

	return writeKeyToFile(privateKey, "client-tls-key.pem")
}

func generateSSHCert(caSigner crypto.Signer) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}

	caSSHSigner, err := ssh.NewSignerFromKey(caSigner)
	if err != nil {
		return err
	}

	userCert := &ssh.Certificate{
		Serial:          uint64(1),
		Key:             signer.PublicKey(),
		KeyId:           "daf-user-cert",
		ValidPrincipals: []string{"daf"},
		CertType:        ssh.UserCert,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().AddDate(0, 0, 1).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-port-forwarding": "",
				"permit-pty":             "",
			},
			CriticalOptions: map[string]string{
				"force-command":  "'echo 1'",
				"source-address": "'198.51.100.0/24,203.0.113.0/26'",
			},
		},
	}

	err = userCert.SignCert(rand.Reader, caSSHSigner)
	if err != nil {
		return nil
	}

	err = writeToFile("user-ssh.pem", ssh.MarshalAuthorizedKey(userCert))
	if err != nil {
		return err
	}

	serverCert := &ssh.Certificate{
		Serial:          uint64(1),
		Key:             signer.PublicKey(),
		KeyId:           "daf-server-cert",
		ValidPrincipals: []string{"daf-server.daf.com"},
		CertType:        ssh.HostCert,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().AddDate(0, 0, 1).Unix()),
	}

	err = serverCert.SignCert(rand.Reader, caSSHSigner)
	if err != nil {
		return nil
	}

	return writeToFile("server-ssh.pem", ssh.MarshalAuthorizedKey(serverCert))

}

func writeX509ToFile(certBytes []byte, filename string) error {
	certPem, err := pemEncodeCertificate(certBytes)
	if err != nil {
		return err
	}

	return writeToFile(filename, certPem)

}

func writeKeyToFile(key ed25519.PrivateKey, filename string) error {
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPem, err := pemEncodePrivateKey(kb)
	if err != nil {
		return err
	}

	return writeToFile(filename, keyPem)
}

func writeToFile(filename string, data []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func pemEncodeCertificate(cert []byte) ([]byte, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func pemEncodePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: key.([]byte),
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

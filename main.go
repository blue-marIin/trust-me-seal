package main

import (
	"net"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"
	"software.sslmate.com/src/go-pkcs12"
	"math/big"
)

const caConfigPath = "ca-config.json"
const outputDir = "output"

type CAConfig struct {
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	CommonName         string `json:"commonName"`
	ValidForDays       int    `json:"validForDays"`
	IsCA               bool   `json:"isCA"`
	KeyUsageCertSign   bool   `json:"keyUsageCertSign"`
}

func main() {
	ipValue := flag.String("ip", "", "Print server PC's IP address")
	passphrase := flag.String("passphrase", "", "Passphrase to encrypt PKCS#12 files")

	flag.Parse()

	if (*ipValue == "" || *passphrase == "") {
		fmt.Println("You must provide the IP address and passphrase.\neg: ./trustmeseal.exe --ip 192.168.1.1 --passphrase password123")
		os.Exit(1)
	}

	os.MkdirAll(outputDir, os.ModePerm)

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey

	var config CAConfig
	configData, err := os.ReadFile(caConfigPath)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		panic(err)
	}
	caCert, caKey = generateSelfSignedCA(config, outputDir, *passphrase)

	// Generate local print server's cert
	generateCertificate(*ipValue, outputDir, *passphrase, caCert, caKey)
}

func generateSelfSignedCA(cfg CAConfig, outputDir, passphrase string) (*x509.Certificate, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)

	template := x509.Certificate{
		SerialNumber:          bigInt(),
		Subject:               pkix.Name{Country: []string{cfg.Country}, Organization: []string{cfg.Organization}, OrganizationalUnit: []string{cfg.OrganizationalUnit}, CommonName: cfg.CommonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, cfg.ValidForDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Save PKCS#12 CA
	pfxData, _ := pkcs12.Encode(rand.Reader, priv, cert, nil, passphrase)
	os.WriteFile(outputDir+"/ca_cert.p12", pfxData, 0600)

	certOut, _ := os.Create(outputDir + "/ca_cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certOut.Close()

	// CA's key not used in Clodop or for Windows certs
	// keyOut, _ := os.Create(outputDir + "/ca_key.pem")
	// pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	// keyOut.Close()

	return cert, priv
}

func generateCertificate(ipStr, outputDir, passphrase string, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Printf("Invalid IP address: %s\n", ipStr)
		return
	}

	template := x509.Certificate{
		SerialNumber: bigInt(),
		Subject: pkix.Name{
			CommonName: ipStr,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		IPAddresses: []net.IP{ip},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	var certDER []byte
	if caCert != nil && caKey != nil {
		certDER, _ = x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	} else {
		// if self-signed
		certDER, _ = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	}

	cert, _ := x509.ParseCertificate(certDER)

	// Save PKCS#12
	pfxData, _ := pkcs12.Encode(rand.Reader, priv, cert, nil, passphrase)
	os.WriteFile(outputDir+"/cert.p12", pfxData, 0600)

	certOut, _ := os.Create(outputDir + "/cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certOut.Close()

	keyOut, _ := os.Create(outputDir + "/key.key")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func bigInt() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

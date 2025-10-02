package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

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
	printerDns := flag.String("dns", "", "Print server's address")
	passphrase := flag.String("passphrase", "", "Passphrase to encrypt PKCS#12 files")
	outputDir := flag.String("output", "output", "Output file path")
	caConfig := flag.String("ca-config", "ca-config.json", "CA config JSON file location")
	exportRootPK := flag.Bool("export-root-pk", false, "Export CA private key")

	flag.Parse()

	if *printerDns == "" || *passphrase == "" {
		fmt.Println("You must provide the DNS of the print server PC and a passphrase.\neg: ./trust-me-seal-cli.exe --dns printserver.local --passphrase changeit")
		os.Exit(1)
	}

	err := os.MkdirAll(*outputDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey

	var config CAConfig
	configData, err := os.ReadFile(*caConfig)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		panic(err)
	}

	caCert, caKey = generateSelfSignedCA(config, *outputDir, *passphrase, *exportRootPK)

	// Generate local print server's cert
	generateCertificate(*printerDns, *outputDir, *passphrase, caCert, caKey)

	fmt.Println("Finished generating certificates - please check the output folder.")
}

func generateSelfSignedCA(cfg CAConfig, outputDir string, passphrase string, exportRootPK bool) (*x509.Certificate, *rsa.PrivateKey) {
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
	pfxData, _ := pkcs12.Modern.Encode(priv, cert, nil, passphrase)
	os.WriteFile(outputDir+"/TRUSTED_ROOT.p12", pfxData, 0600)

	certOut, _ := os.Create(outputDir + "/openssl_root_certfile.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certOut.Close()

	// Not outputting CA's private key by default - intended ephemeral/single-use CA cert
	if exportRootPK {
		keyOut, _ := os.Create(outputDir + "/ca_key.pem")
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		keyOut.Close()
	}

	return cert, priv
}

func generateCertificate(ipStr string, outputDir string, passphrase string, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
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
	}

	cert, _ := x509.ParseCertificate(certDER)

	// Save PKCS#12
	pfxData, _ := pkcs12.Modern.Encode(priv, cert, nil, passphrase)
	os.WriteFile(outputDir+"/personal_certificate.p12", pfxData, 0600)

	certOut, _ := os.Create(outputDir + "/openssl_certfile.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certOut.Close()

	keyOut, _ := os.Create(outputDir + "/openssl_key_file.key")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func bigInt() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

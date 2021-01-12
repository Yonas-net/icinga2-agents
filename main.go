package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/Yonas-net/icinga2-agents/lib/base"
	"io/ioutil"
	"log"
	"math/big"
	_ "os"
	"time"
)

type Encoder struct {
	JSONRPC string  `json:"jsonrpc"`
	Method  string  `json:"method"`
	Params  ConfigInfo `json:"params"`
}

type ConfigInfo map[string]string

func main()  {
	port := flag.Int("port", 0, "On which port the connection should be established.")
	host := flag.String("host", " ", "Host Name or IP Address with which a connection should be established.")
	parallel := flag.Bool("parallel", false, "Whether the connection should be established serially or parallel.")
	cakey := flag.String("cakey", " ", "Certificate Authority (CA) private key.")
	cacert := flag.String("cacert", " ", "Certificate Authority (CA) crt file.")
	concurrency := flag.Int("concurrency", 0, "How many times should the connection be established.")
	sleep := flag.Duration("sleep", 0, "Sleep seconds before it starts sending crt request messages.")
	duration := flag.Int("duration", 0, "For how many days should the certificates be valid.")
	flag.Parse()

	rootCAs, err := ioutil.ReadFile(*cacert)
	if err != nil {
		log.Fatalf("CLIENT: Error while loading CA files %s", err.Error())
	}

	key, err := ioutil.ReadFile(*cakey)
	if err != nil {
		log.Fatalf("CLIENT: Failed to load Certificate Authority private key: %s", err.Error())
	}

	decode, _ := pem.Decode(key)
	if decode == nil {
		log.Fatalf("CLIENT: Failed to parse Certificate Authority private key")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(decode.Bytes)
	if err != nil {
		log.Fatalf("CLIENT: Unable to parse RSA private key: %s", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("CLIENT: Failed to generate new private key %s", err)
	}

	privatePem := new(bytes.Buffer)
	 pem.Encode(privatePem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	block, _ := pem.Decode(rootCAs)
	if block == nil {
		log.Fatalf("CLIENT: Failed to parse certificate PEM")
	}
	CAuthority, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("CLIENT: Failed to parse certificate: %s", err.Error())
	}

	tlsConfigs := make(map[int]*tls.Config)

	for i := 0; i < *concurrency; i++ {
		_ , certPem := GenerateCertificate(CAuthority, parsedKey, privateKey, duration, fmt.Sprintf("localhost%d", i))

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(rootCAs)

		cert, err := tls.X509KeyPair(certPem.Bytes(), privatePem.Bytes())
		if err != nil {
			log.Fatalf("CLIENT: Failed to load certificate and private key: %s", err.Error())
		}

		conf := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAnyClientCert,
			ClientCAs: caCertPool,
			InsecureSkipVerify: true,
		}

		conf.Rand = rand.Reader
		tlsConfigs[i] = conf
	}

	message := EncodeOutgoingMessage()
	Addr := fmt.Sprintf("%s%s%d", *host, ":", *port)

	for i := 0; i < *concurrency; i++ {
		if *parallel {
			go ProcessOutgoingConnection(Addr, tlsConfigs[i], sleep, message)
		} else {
			ProcessOutgoingConnection(Addr, tlsConfigs[i], sleep, message)
		}
	}

	fmt.Scanln()
}

func EncodeOutgoingMessage() []byte {
	encoder := &Encoder{
		JSONRPC: "2.0",
		Method: "pki::RequestCertificate",
		Params: map[string]string{
			"ticket": " ",
		},
	}

	message, err := json.Marshal(&encoder)
	if err != nil{
		log.Printf("CLIENT: JsonRpcConnection: Error while encoding JSRPC message. %s", err)
	}

	return message
}

func ProcessOutgoingConnection(Addr string, conf *tls.Config, sleep *time.Duration, message []byte)  {
	conn, err := tls.Dial("tcp", Addr, conf)

	defer conn.Close()
	if err != nil {
		log.Fatalf("CLIENT: Failed to connect: %s", err.Error())
	}

	log.Printf("CLIENT: Connect to %s succeed", Addr)
	time.Sleep(*sleep)

	log.Printf("CLIENT: JsonRpcConnection: Sending pki::RequestCertificate JSRPC message: %s", message)

	err = base.WriteNetStringToStream(conn, message)

	if err != nil {
		log.Printf("CLIENT: JsonRpcConnection: Error while sending json encoded JSRPC message: %s", err)
	}
}

func GenerateCertificate(CACert *x509.Certificate, CAKey *rsa.PrivateKey, priv *rsa.PrivateKey, days *int, endpoint string) (*x509.Certificate, *bytes.Buffer) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 160)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatal("CLIENT: Failed to generate serial number: " + err.Error())
	}

	certificateTemplate := x509.Certificate{
		SerialNumber:   		serialNumber,
		Version: 				2,
		Subject:				pkix.Name{ CommonName: endpoint },
		SignatureAlgorithm:		x509.SHA256WithRSA,
		NotBefore:      		time.Now(),
		NotAfter:       		time.Now().AddDate(0, 0, *days),
		IsCA:           		false,
		DNSNames: 				[]string{endpoint},
		BasicConstraintsValid:  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, CACert, &priv.PublicKey, CAKey)
	if err != nil {
		log.Fatalf("CLIENT: Failed to create certificate: %s", err.Error())
	}

	// Uncomment the following codes to store the generated crt in a file
	/*certOut, err := os.Create("ha-cluster.crt")
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		log.Fatalf("Failed to write data to ha-cluster.crt: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing ha-cluster.crt: %v", err)
	}*/

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("CLIENT: Failed to parse certificate: %s", err.Error())
	}

	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return cert, certPem
}

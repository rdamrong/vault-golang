package main

import (
	"context"
	"io/ioutil"
	"net/http"

	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"

	vault "github.com/hashicorp/vault/api"
)

func main() {
	caCert := "./myvault/tls/ca.crt"
	cert := ""
	key := ""

	config := vault.DefaultConfig()

	config.Address = "https://127.0.0.1:8200"

	tlsConfig := &tls.Config{}
	if cert != "" && key != "" {
		clientCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		tlsConfig.BuildNameToCertificate()
	}
	if caCert != "" {
		ca, err := ioutil.ReadFile(caCert)
		if err != nil {
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = caCertPool
	}

	config.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("unable to initialize Vault client: %v", err)
	}

	// Authenticate
	client.SetToken("hvs.sORJ5Tcmt3GGGmesCSU9le5l")

	// Read a secret from the default mount path for KV v2 in dev mode, "secret"
	secret, err := client.KVv2("myproject/").Get(context.Background(), "project1")
	if err != nil {
		log.Fatalf("unable to read secret: %v", err)
	}


	fmt.Printf("Secret access_id at myproject/project1 is %s\n", secret.Data["access_id"])
	fmt.Printf("Secret access_key at myproject/project1 is %s\n", secret.Data["access_key"])


}

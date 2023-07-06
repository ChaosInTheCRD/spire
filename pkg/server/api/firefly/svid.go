package firefly

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"

	// dumpster-spire
	apis "gitlab.com/venafi/vaas/applications/tls-protect/dmi/cli/firefly-ca/pkg/apis/proto/certificates/v1alpha1"
	csrapi "gitlab.com/venafi/vaas/applications/tls-protect/dmi/cli/firefly-ca/pkg/apis/proto/certificates/v1alpha1/v1alpha1service"
)

func CreateSVID(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	csrBlock := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}

	csrPEM := pem.EncodeToMemory(&csrBlock)

	ffapi := NewFireflyAPI("firefly.firefly.svc.cluster.local:8081")
	fcsr := csrapi.CreateCertificateSigningRequest{
		Request: &apis.CertificateSigningRequest{
			Request: csrPEM,
			// KeyType: &keytype,
			// ValidityPeriod: &valid,
			PolicyName: os.Getenv("POLICY_NAME"),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	certchain, err := ffapi.Create(ctx, &fcsr)
	if err != nil {
		log.Fatalf("Oops: %v\n", err)
	}

	return convertResponseToCerts(certchain), nil
}

func convertResponseToCerts(chain []byte) []*x509.Certificate {
	var pemBlocks []*pem.Block

	for {
		pemBlock, rest := pem.Decode(chain)
		if pemBlock == nil {
			break
		}
		pemBlocks = append(pemBlocks, pemBlock)
		chain = rest
	}

	// Step 2: Parse each PEM block and construct x509.Certificate objects
	var certs []*x509.Certificate

	for _, pemBlock := range pemBlocks {
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			log.Printf("Failed to parse certificate: %v", err)
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}

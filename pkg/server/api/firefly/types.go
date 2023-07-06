package firefly

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	// dumpster-spire
	csrapi "gitlab.com/venafi/vaas/applications/tls-protect/dmi/cli/firefly-ca/pkg/apis/proto/certificates/v1alpha1/v1alpha1service"
)

type FireflyAPI struct {
	client csrapi.CertificateSigningRequestServiceClient
}

type jwt struct {
	token string
}

func (j jwt) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + j.token,
	}, nil
}

func (j jwt) RequireTransportSecurity() bool {
	log.Println("dumpster-spire: Called RequireTransportSecurity")
	return true
}

func NewFireflyAPI(url string) FireflyAPI {
	// jwtCreds, err := jwt.NewFromTokenFile(os.Getenv("TOKEN"))
	jwtCreds := jwt{os.Getenv("TOKEN")}

	var tlsConf tls.Config
	tlsConf.InsecureSkipVerify = true
	creds := credentials.NewTLS(&tlsConf)

	conn, err := grpc.Dial(url,
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(jwtCreds),
	)
	if err != nil {
		log.Fatalf("dumpster-spire: %v", err)
	}

	client := csrapi.NewCertificateSigningRequestServiceClient(conn)
	return FireflyAPI{client: client}
}

func (c *FireflyAPI) Create(ctx context.Context, csr *csrapi.CreateCertificateSigningRequest) ([]byte, error) {
	resp, err := c.client.Create(ctx, csr)
	if err != nil {
		return nil, fmt.Errorf("creation Failure: %w", err)
	}
	return resp.GetResponse().CertificateChain, nil
}

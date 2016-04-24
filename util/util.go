package util

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"farm.e-pedion.com/repo/config"
)

var (
	certPool       *x509.CertPool
	securityConfig = config.BindSecurityConfiguration()
)

// NewUUID generates a random UUID according to RFC 4122
func NewUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

//GetCertPool returns a tls certificate pool with the configured certificate inside it
func GetCertPool() (*x509.CertPool, error) {
	if certPool == nil {
		certData, err := ioutil.ReadFile(securityConfig.CustomSSLCertificatePath)
		if err != nil {
			return nil, err
		}
		log.Printf("uti.AppendCustomTLSCertificate: CertificatePath=%v", securityConfig.CustomSSLCertificatePath)
		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(certData)
		if !ok {
			return nil, errors.New("util.CanotUseCustomSSLCertificatePath: Message='Impossible to set the custom certificate file into the x509 Pool'")
		}
	}
	return certPool, nil
}

//GetTLSHttpClient returns a a tls transport http client
func GetTLSHttpClient() (*http.Client, error) {
	if securityConfig.UseCustomSSLCertificate {
		tempCertPool, err := GetCertPool()
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				//InsecureSkipVerify: true,
				RootCAs: tempCertPool,
			},
			//DisableCompression: true,
		}
		return &http.Client{Transport: tr}, nil

	}
	return &http.Client{}, nil
}

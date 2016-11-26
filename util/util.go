package util

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"

	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"github.com/satori/go.uuid"
)

var (
	idSeed               [24]byte
	idCounter            uint64
	certPool             *x509.CertPool
	customSSLCertPathKey = "security.custom_ssl_certificate_path"
	useCustomSSLCertKey  = "security.client_use_custom_ssl_certificate"
)

func init() {
	_, err := rand.Read(idSeed[:])
	if err != nil {
		panic(err)
	}
}

// NewUUID generates a new random v4 UUID, it is RFC 4122 compliant
func NewUUID() (string, error) {
	uid := uuid.NewV4()
	return uid.String(), nil
}

// NewID generates a new random 16 bytes id, it ignores the RFC 4122
func NewID() string {
	id := NewRawID()
	return fmt.Sprintf("%x", id[:16])
}

// NewLongID generates a new random 24 bytes id, it ignores the RFC 4122
func NewLongID() string {
	id := NewRawID()
	return fmt.Sprintf("%x", id)
}

// NewRawID returns the next raw UUID bytes from the generator
// Only the first 8 bytes can differ from the previous
// UUID, so taking a slice of the first 16 bytes
// is sufficient to provide a somewhat less secure 128 bit UUID.
//
// It is OK to call this method concurrently.
func NewRawID() [24]byte {
	newCounter := atomic.AddUint64(&idCounter, 1)
	var counterBytes [8]byte
	binary.LittleEndian.PutUint64(counterBytes[:], newCounter)

	id := idSeed
	for i, b := range counterBytes {
		id[i] ^= b
	}
	return id
}

//GetCertPool returns a tls certificate pool with the configured certificate inside it
func GetCertPool() (*x509.CertPool, error) {
	if certPool == nil {
		// certData, err := ioutil.ReadFile(securityConfig.CustomSSLCertificatePath)
		certData, err := ioutil.ReadFile(config.GetString(customSSLCertPathKey))
		if err != nil {
			return nil, err
		}
		logger.Info("AppendCustomTLSCertificate",
			logger.String("CertificatePath", config.GetString(customSSLCertPathKey)),
		)
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
	if config.GetBool(useCustomSSLCertKey) {
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

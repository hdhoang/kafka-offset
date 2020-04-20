package util

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"hash"
	"io/ioutil"

	"github.com/sirupsen/logrus"
	"github.com/xdg/scram"
)

// GetTLSConfiguration build TLS configuration for kafka
func GetTLSConfiguration(caFile string, certFile string, keyFile string, insecure bool) (*tls.Config, bool, error) {
	logrus.Debugf("configure tls %s %s %s %t", caFile, certFile, keyFile, insecure)
	if (caFile == "" && (certFile == "" || keyFile == "")) && !insecure {
		return nil, false, nil
	}
	t := &tls.Config{}
	if caFile != "" {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, false, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		t.RootCAs = caCertPool
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, false, err
		}
		t.Certificates = []tls.Certificate{cert}
	}

	t.InsecureSkipVerify = insecure
	logrus.Debugf("TLS config %+v", t)

	return t, true, nil
}

// GetSASLConfiguration build SASL configuration for kafka
func GetSASLConfiguration(username string, password string) (string, string, bool) {
	if username != "" && password != "" {
		return username, password, true
	}
	return "", "", false
}

// https://github.com/Shopify/sarama/blob/master/examples/sasl_scram_client/scram_client.go
var SHA256 scram.HashGeneratorFcn = func() hash.Hash { return sha256.New() }
var SHA512 scram.HashGeneratorFcn = func() hash.Hash { return sha512.New() }

type XDGSCRAMClient struct {
	*scram.Client
	*scram.ClientConversation
	scram.HashGeneratorFcn
}

func (x *XDGSCRAMClient) Begin(userName, password, authzID string) (err error) {
	x.Client, err = x.HashGeneratorFcn.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	x.ClientConversation = x.Client.NewConversation()
	return nil
}

func (x *XDGSCRAMClient) Step(challenge string) (response string, err error) {
	response, err = x.ClientConversation.Step(challenge)
	return
}

func (x *XDGSCRAMClient) Done() bool {
	return x.ClientConversation.Done()
}

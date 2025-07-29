// Copyright 2012-present Oliver Eilhard. All rights reserved.
// Use of this source code is governed by a MIT-license.
// See http://olivere.mit-license.org/license.txt for details.

package v4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	// service constants for the service to be signed.
	service = "es"
)

// NewV4SigningClient returns an *http.Client that will sign all requests with AWS V4 Signing.
func NewV4SigningClient(creds aws.CredentialsProvider, region string) *http.Client {
	return NewV4SigningClientWithHTTPClient(creds, region, &http.Client{})
}

// NewV4SigningClientWithHTTPClient returns an *http.Client that will sign all requests with AWS V4 Signing.
func NewV4SigningClientWithHTTPClient(creds aws.CredentialsProvider, region string, httpClient *http.Client) *http.Client {
	return &http.Client{
		Transport: Transport{
			client:  httpClient,
			creds:   creds,
			signer:  v4.NewSigner(),
			region:  region,
			service: service,
		},
	}
}

// Transport is a RoundTripper that will sign requests with AWS V4 Signing
type Transport struct {
	client  *http.Client
	creds   aws.CredentialsProvider
	signer  *v4.Signer
	region  string
	service string
}

func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	payloadHash, newReader, err := hashPayload(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = newReader

	ctx := req.Context()
	creds, err := t.creds.Retrieve(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	req.Header.Set("Date", now.Format(time.RFC3339))
	err = t.signer.SignHTTP(ctx, creds, req, payloadHash, t.service, t.region, now)
	if err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}
	return t.client.Do(req)
}

func hashPayload(r io.ReadCloser) (payloadHash string, newReader io.ReadCloser, err error) {
	var payload []byte
	if r == nil {
		payload = []byte("")
	} else {
		payload, err = ioutil.ReadAll(r)
		if err != nil {
			return
		}
		newReader = ioutil.NopCloser(bytes.NewReader(payload))
	}
	hash := sha256.Sum256(payload)
	payloadHash = hex.EncodeToString(hash[:])
	return
}

//  Copyright 2018 Google LLC
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at

//        https://www.apache.org/licenses/LICENSE-2.0

//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//	limitations under the License.

// Package grpcutil contains a set of common libraries used across minions and overlord.
// We really need to keep this to a minimum and avoid the kitchen-sink effect.
package grpcutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GetSslServerCreds reads the SSL keys and certs and generates the required options for a GRPC server.
// If the keys and certs have both been left blank, it will return nil. If only one is set it will return
// an error. If a CA certificate is provided, it will also set up client authentication using it.
func GetSslServerCreds(certPath string, keyPath string, caCertPath string) (grpc.ServerOption, error) {
	if certPath == "" && keyPath == "" {
		log.Println("no certificate and key set")
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("please specify both an SSL key and certificate")
	}
	// Create the TLS credentials
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	var creds credentials.TransportCredentials
	if caCertPath == "" {
		log.Println("no CA set, all clients will be able to connect")
		creds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{certificate},
		})
		return grpc.Creds(creds), nil
	}
	cas := x509.NewCertPool()
	ca, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	if ok := cas.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("failed while creating CA pool for client verification. Check the CA cert")
	}

	log.Println("CA set and configured, enforcing client authentication")
	creds = credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cas,
	})
	return grpc.Creds(creds), nil
}

// GetSslClientOptions returns dial options by looking at SSL related
// flags - essentially, either ingests a CA certificate to validate
// the server or just gives up validating anything at all.
func GetSslClientOptions(serverAddress string, caCertPath string) (grpc.DialOption, error) {
	if caCertPath == "" {
		log.Println("WARNING: no CA specified. We will NOT check server's SSL certs")
		return grpc.WithInsecure(), nil
	}
	// NOTE: this is where we'd put client certs if we ever want to.
	cas := x509.NewCertPool()
	ca, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("could not read ca certificate: %s", err)
	}
	if ok := cas.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("failed to append ca certs")
	}
	log.Println("CA loaded, will check server SSL certs. That's good.")
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    cas,
		ServerName: serverAddress,
	})
	return grpc.WithTransportCredentials(creds), nil
}

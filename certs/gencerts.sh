#!/bin/sh

openssl ecparam -out ca.key -name prime256v1 -genkey
openssl req -new -sha256 -key ca.key -out ca.csr -batch -subj '/CN=CA'
openssl x509 -req -sha256 -days 3650 -in ca.csr -signkey ca.key -out ca.crt

openssl ecparam -out localhost.key -name prime256v1 -genkey
openssl req -new -sha256 -key localhost.key -out localhost.csr -batch -subj '/CN=localhost'
openssl x509 -req -sha256 -days 3650 -in localhost.csr -CA ca.crt -CAkey ca.key -out localhost.crt

openssl genpkey -out client.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048
openssl req -new -sha256 -key client.key -out client.csr -batch -subj '/CN=client'
openssl x509 -req -sha256 -days 3650 -in client.csr -CA ca.crt -CAkey ca.key -out client.crt
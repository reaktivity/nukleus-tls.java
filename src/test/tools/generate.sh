#!/bin/bash
#
# Copyright 2016-2021 The Reaktivity Project
#
# The Reaktivity Project licenses this file to you under the Apache License,
# version 2.0 (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#


CA_PASS=generated
CERT_PASS=generated

function print_cert()
{
  CERT=$1
  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Printing certificate ${CERT}"
  echo "------------------------------------------------------------------------------"
  openssl x509 -noout -text -in ${CERT}
}

function print_req()
{
  CERT=$1
  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Printing certificate request ${CERT}"
  echo "------------------------------------------------------------------------------"
  openssl req -noout -text -in ${CERT}
}

function print_key()
{
  KEY=$1
  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Printing key ${KEY}"
  echo "------------------------------------------------------------------------------"
  openssl rsa -noout -text -in ${KEY}
}

create_ca()
{
  CA_ALIAS=$1
  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Generate ca keypair: ${CA_ALIAS}.jks"
  echo "------------------------------------------------------------------------------"
  keytool -genkeypair -keystore ${CA_ALIAS}.jks -storepass ${CA_PASS} -keypass ${CA_PASS} -alias ${CA_ALIAS} -dname "C=US, ST=California, O=Reaktivity, OU=Development, CN=${CA_ALIAS}" -validity 3650 -keyalg RSA -ext bc:c

  # The previous command generates a key pair (a public key and associated private key). Wraps the
  # public key into an X.509 v3 self-signed certificate, which is stored as a single-element certificate
  # chain. This certificate chain and the private key are stored in a new keystore entry identified by alias.
  # To view the keystore: keytool -list -v -keystore democa.jks -storepass capass

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Export ca certificate in pem format: ${CA_ALIAS}.crt"
  echo "------------------------------------------------------------------------------"
  keytool -keystore ${CA_ALIAS}.jks -storepass ${CA_PASS} -alias ${CA_ALIAS} -exportcert -rfc > ${CA_ALIAS}.crt

  print_cert ${CA_ALIAS}.crt

  # Keytool cannot export a private key. So save the keystore in P12 format, which can then be used
  # by openssl to export the private key.

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Export keystore to P12 format: ${CA_ALIAS}.p12"
  echo "------------------------------------------------------------------------------"
  keytool -importkeystore -srckeystore ${CA_ALIAS}.jks -srcstorepass ${CA_PASS} -srcalias ${CA_ALIAS} -destkeystore ${CA_ALIAS}.p12 -deststorepass ${CA_PASS} -deststoretype PKCS12

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Export private key in pem format: ${CA_ALIAS}.key"
  echo "------------------------------------------------------------------------------"
  openssl pkcs12 -in ${CA_ALIAS}.p12 -passin pass:${CA_PASS} -nodes -nocerts -out ${CA_ALIAS}.key

  print_key ${CA_ALIAS}.key
}

create_cert()
{
  CA_ALIAS=$1
  CERT_ALIAS=$2
  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Generate cert keypair: ${CERT_ALIAS}.jks"
  echo "------------------------------------------------------------------------------"
  keytool -genkeypair -keystore ${CERT_ALIAS}.jks -storepass ${CERT_PASS} -keypass ${CERT_PASS} -alias ${CERT_ALIAS} -dname "C=US, ST=California, O=Kaazing, OU=Development, CN=${CERT_ALIAS}" -validity 3650 -keyalg RSA

  # The previous command generates a key pair (a public key and associated private key). Wraps the
  # public key into an X.509 v3 self-signed certificate, which is stored as a single-element certificate
  # chain. This certificate chain and the private key are stored in a new keystore entry identified by alias.
  # To view the keystore: keytool -list -v -keystore democa.jks -storepass capass

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Create certificate signing request: ${CERT_ALIAS}.csr"
  echo "------------------------------------------------------------------------------"
  keytool -keystore ${CERT_ALIAS}.jks -storepass ${CERT_PASS} -alias ${CERT_ALIAS} -certreq -rfc > ${CERT_ALIAS}.csr

  print_req ${CERT_ALIAS}.csr

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Sign the csr: ${CERT_ALIAS}.crt"
  echo "------------------------------------------------------------------------------"
 # keytool -keystore ${CA_ALIAS}.jks -storepass ${CA_PASS} -keypass ${CA_PASS} -gencert -alias ${CA_ALIAS} -ext ku:c=dig,keyenc -rfc -validity 1800 < ${CERT_ALIAS}.csr > ${CERT_ALIAS}.crt
  keytool -keystore ${CA_ALIAS}.jks -storepass ${CA_PASS} -keypass ${CA_PASS} -gencert -alias ${CA_ALIAS} -ext ku:c=dig,keyenc -rfc -validity 1800 < ${CERT_ALIAS}.csr > ${CERT_ALIAS}.crt

  print_cert ${CERT_ALIAS}.crt

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Export keystore to P12 format: ${CERT_ALIAS}.p12"
  echo "------------------------------------------------------------------------------"
  keytool -importkeystore -srckeystore ${CERT_ALIAS}.jks -srcstorepass ${CERT_PASS} -srcalias ${CERT_ALIAS} -destkeystore ${CERT_ALIAS}.p12 -deststorepass ${CERT_PASS} -deststoretype PKCS12

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Export private key in pem format: ${CERT_ALIAS}.key"
  echo "------------------------------------------------------------------------------"
  openssl pkcs12 -in ${CERT_ALIAS}.p12 -passin pass:${CERT_PASS} -nodes -nocerts -out ${CERT_ALIAS}.key

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Import the signed certificate: ${CERT_ALIAS}.crt"
  echo "------------------------------------------------------------------------------"
  keytool -keystore ${CERT_ALIAS}.jks -storepass ${CERT_PASS} -keypass ${CERT_PASS} -importcert -alias ${CA_ALIAS} -rfc -noprompt < ${CA_ALIAS}.crt
  keytool -keystore ${CERT_ALIAS}.jks -storepass ${CERT_PASS} -keypass ${CERT_PASS} -importcert -alias ${CERT_ALIAS} -rfc < ${CERT_ALIAS}.crt
  keytool -keystore ${CERT_ALIAS}.jks -storepass ${CERT_PASS} -keypass ${CERT_PASS} -delete -alias ${CA_ALIAS} -noprompt
}

import_cert()
{
  CERT_ALIAS=$1
  DEST_STORE=$2
  keytool -importkeystore -deststorepass ${CERT_PASS} -destkeypass ${CERT_PASS} -destkeystore $DEST_STORE -srckeystore ${CERT_ALIAS}.jks -srcstoretype PKCS12 -srcstorepass ${CERT_PASS} -alias ${CERT_ALIAS}
}

create_cacerts()
{
  CA_ALIAS=$1
  CA_CERTS=$2
  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Import the democa certificate: ${CA_ALIAS}.crt"
  echo "------------------------------------------------------------------------------"
  keytool -keystore $CA_CERTS -storepass ${CA_PASS} -keypass ${CA_PASS} -importcert -alias ${CA_ALIAS} -rfc -noprompt < ${CA_ALIAS}.crt
}

copy()
{
	cp tmp/server.cacerts.jks cacerts 
	cp tmp/server.cacerts.jks trust
	cp tmp/server.cacerts.jks stores/client/trust 

	cp tmp/server.keystore.all.jks keys
	cp tmp/server.keystore.all.jks localhost
	cp tmp/server.keystore.all.jks stores/server/keys 

	cp tmp/server.keystore.all.jks stores/server.want.auth/keys 
	cp tmp/client.cacerts.jks stores/server.want.auth/trust
	cp tmp/client1.jks stores/server.want.auth/k3po.keys 
	cp tmp/server.cacerts.jks stores/server.want.auth/k3po.trust
}

rm -rf  tmp
mkdir tmp
cd tmp

SERVER_CA_ALIAS=DemoCA
create_ca $SERVER_CA_ALIAS
for cn in example.com example.net example.org localhost
do
  create_cert $SERVER_CA_ALIAS $cn
  import_cert $cn server.keystore.all.jks
done
create_cacerts $SERVER_CA_ALIAS server.cacerts.jks 

CLIENT_CA_ALIAS=ClientDemoCA
create_ca $CLIENT_CA_ALIAS
for cn in client1
do
  create_cert $CLIENT_CA_ALIAS $cn
done
create_cacerts $CLIENT_CA_ALIAS client.cacerts.jks 

cd -
copy


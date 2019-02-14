#!/bin/bash

CA_ALIAS=DemoCA
CA_PASS=generated
CERT_PASS=generated

clean()
{
  echo "Clean files from previous run"
  rm -rf ${CA_ALIAS}.jks ${CA_ALIAS}.crt ${CA_ALIAS}.p12 ${CA_ALIAS}.key
  rm -rf keystore.all.jks cacerts.jks
}

clean_cert()
{
  echo "Clean cert files from previous run"
  rm -rf ${CERT_ALIAS}.jks ${CERT_ALIAS}.crt ${CERT_ALIAS}.p12 ${CERT_ALIAS}.key ${CERT_ALIAS}.csr
}

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

create_server_cert()
{
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

import_server_cert()
{
  keytool -importkeystore -deststorepass ${CERT_PASS} -destkeypass ${CERT_PASS} -destkeystore keystore.all.jks -srckeystore ${CERT_ALIAS}.jks -srcstoretype PKCS12 -srcstorepass ${CERT_PASS} -alias ${CERT_ALIAS}
}

create_cacerts()
{

  echo ""
  echo "------------------------------------------------------------------------------"
  echo "Import the democa certificate: ${CA_ALIAS}.crt"
  echo "------------------------------------------------------------------------------"
  keytool -keystore cacerts.jks -storepass ${CA_PASS} -keypass ${CA_PASS} -importcert -alias ${CA_ALIAS} -rfc -noprompt < ${CA_ALIAS}.crt
}

copy()
{
	cp cacerts.jks cacerts 
	cp cacerts.jks trust
	cp cacerts.jks stores/client/trust 

	cp keystore.all.jks keys
	cp keystore.all.jks localhost
	cp keystore.all.jks stores/server/keys 
}

clean
create_ca
for cn in example.com example.net example.org localhost
do
  CERT_ALIAS=$cn
  clean_cert
  create_server_cert
  import_server_cert
done
create_cacerts
copy


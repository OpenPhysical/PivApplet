all: test-certs

test-certs: .PHONY
	# RSA 1024 and RSA 2048 bit keys
	openssl genrsa 1024 2> /dev/null | openssl rsa -inform PEM -outform DER 2> /dev/null > keys/rsa_1024.key
	openssl genrsa 2048 2> /dev/null | openssl rsa -inform PEM -outform DER 2> /dev/null > keys/rsa_2048.key

	# ECC 256
	openssl ecparam -genkey -name prime256v1 -noout -outform DER -out keys/ecc_p_256_private.key
	openssl ec -in keys/ecc_p_256_private.key -inform DER -outform DER -pubout -out keys/ecc_p_256_public.key 2> /dev/null

	# ECC 384
	openssl ecparam -genkey -name secp384r1 -noout -outform DER -out keys/ecc_p_384_private.key
	openssl ec -in keys/ecc_p_384_private.key -inform DER -outform DER -pubout -out keys/ecc_p_384_public.key 2> /dev/null

	# Attestation root
	rm -r ca/
	mkdir -p ca/ ca/certsdb ca/crl ca/certs
	touch ca/index.txt
	/bin/echo "unique_subject = yes" > ca/index.txt.attr
	/bin/echo -n 01 > ca/serial
	openssl ecparam -genkey -name prime256v1 -noout -outform PEM -out keys/attest_root_private.key
	openssl ec -in keys/attest_root_private.key -inform PEM -outform PEM -pubout -out keys/attest_root_public.key 2> /dev/null
	openssl req -new -sha256 -key keys/attest_root_private.key -keyform PEM -out certs/attest_root.csr -subj '/CN=Attestation Root/'
	openssl req -x509 -sha256 -days 3650 -key keys/attest_root_private.key -keyform PEM -in certs/attest_root.csr -out certs/attest_root.pem -config openssl.cnf -extensions attest_ca

	# Attestation cert
	openssl genrsa 2048 2> /dev/null | openssl rsa -inform PEM -outform DER 2> /dev/null > keys/attest_cert.key
	openssl req -new -sha256 -key keys/attest_cert.key -keyform DER -out certs/attest_cert.csr -subj '/CN=Attestation Cert/'
	openssl ca -batch -in certs/attest_cert.csr -extensions attest_cert -config openssl.cnf -out certs/attest_cert.pem -days 3650
	openssl x509 -in certs/attest_cert.pem -out certs/attest_cert.der -inform PEM -outform DER
.PHONY:

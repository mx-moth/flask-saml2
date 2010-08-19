#!/bin/bash
#Thanks to http://robinelvin.wordpress.com/2009/09/04/saml-with-django/
echo "** This utility will create the OpenSSL key and certificate for the keys app."
type -P openssl &>/dev/null || {
    echo "** This utility requires openssl but it's not installed.  Aborting." >&2;
    exit 1;
}
echo "** Starting OpenSSL Interaction ------------------------------------"
openssl genrsa > private-key.pem
openssl req -new -x509 -key private-key.pem -out certificate.pem -days 365
echo "** Finished OpenSSL Interaction ------------------------------------"
echo "** These keys were created:"
ls -l private-key.pem
ls -l certificate.pem
echo "** Finished."

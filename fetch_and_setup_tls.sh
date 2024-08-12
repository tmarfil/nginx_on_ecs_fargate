#!/bin/bash

# Set secret ID
AWS_SECRET_ID='MyTlsCertAndKey1'

# TLS_CERT_AND_KEY environment variable found?
if [ -n "$TLS_CERT_AND_KEY" ]; then
    echo "$TLS_CERT_AND_KEY" > /tmp/secret.json
else
    echo "TLS_CERT_AND_KEY not found" > /tmp/log.txt
fi

# Extract the certificate and key files rom AWS_SECRET_ID
aws secretsmanager get-secret-value --secret-id "$AWS_SECRET_ID" \
          | jq -r '.SecretString | fromjson | .certificate' > /etc/nginx/ecdsa_certificate.pem

aws secretsmanager get-secret-value --secret-id "$AWS_SECRET_ID" \
          | jq -r '.SecretString | fromjson | .private_key' > /etc/nginx/ecdsa_private_key.pem

# Set permissions on the certificate and key files
chmod 600 /etc/nginx/ecdsa_certificate.pem /etc/nginx/ecdsa_private_key.pem

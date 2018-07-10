#!/usr/bin/env bash

usage ()
{
    echo ""
    echo "Usage: $(basename 0) [OPTION] HOST[:PORT]"
    echo ""
    echo "Verify that a generic SSL/TLS client can connect to an SSL server."
    echo ""
    echo "  --show-certs        Show verbose certificate outout"
    echo "  --show-states       Show steps in SSL handshake"
    echo "  --"
    echo ""
}

#TODO things to learn:
# -bind vs -connect
# -servername
# -cert                 Client certificate that we provide if and only if the server requests a certificate (client-side auth)
# -cert_chain           Related to -cert (client-side). Can use -CAPath instead?
# -key                  Private key file. If not specified, the certificate file will be used.
# -CApath               Must be in hash format!
#                       Directory that contains CA used in server-side authentication
#                       Also used when building client certificate chain.
# -CAfile               Use a file for the CA instead of a hashed directory.
# -requestCAfile        TLS 1.3 only
# -showcerts            Display the server's certificate list. Useful if server-side authentication fails.
# -state
# -ssl3, -tls1, -tls1_1, -tls1_2, -tls1_3, -no_ssl3, -no_tls1, -no_tls1_1, -no_tls1_2, -no_tls1_3
#                       Enable or disable specific protocols
# -partial_chain        Do not require a root CA in the certificate chain

# R to renegotiate
# Q to quit

# openssl s_client \
    # -connect localhost:8484 \
    # -CAfile keys/ca.crt \
    # -key keys/client_unencrypted_key.key \
    # -state
    # -brief \

    # -CAfile /tftpboot/cert_vonage.pem \
    # -CApath /etc/ssl/certs

# openssl s_client \
    # -connect 10.0.1.34:5061 \
    # -CAfile keys/ca.crt \
    # -key keys/client.key \
    # -cert keys/client.crt \
    # -state

echo 'command'
COMMAND="openssl s_client \
    -connect sip-785500b.accounts.qa7.vocal-qa.com:10002 \
    -CAfile /usr/share/ca-certificates/mozilla/DigiCert_Global_Root_CA.crt \
    -verify_hostname __sip-785500b.accounts.qa7.vocal-qa.com \
    -verify_return_error -quiet"
OUTPUT=$( ${COMMAND} 2>&1 )

echo '1'
echo $OUTPUT
echo '2'
if printf "%s" "$OUTPUT" | grep 'verify error'; then
    exit 1
else
    exit 0
fi

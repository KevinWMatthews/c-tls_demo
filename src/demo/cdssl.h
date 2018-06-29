#ifndef CDSSL_INCLUDED
#define CDSSL_INCLUDED

// Technically we should hide this, but wrapping the SSL_CTX struct is more effort than this demo is worth.
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/*
 * Initialize the SSL library and set up the IO handle for printing errors.
 *
 * Do not call this function twice!
 */
void initialize_ssl_library(void);

/*
 * The SSL library itself does not need to be uninitialized.
 */


/*
 * Initialize and configure the SSL context.
 *
 * This context applies to all SSL connections made in the the program.
 *
 * verify_options is a bitmask.
 * Valid options for a client are:
 *      SSL_VERIFY_NONE                     Continue if server does not provide cert
 *      SSL_VERIFY_PEER                     Fail if server does not provide cert
 *
 * Valid options for a server are:
 *      SSL_VERIFY_NONE                     Do not send certificate request to client
 *      SSL_VERIFY_PEER                     Send certificate request. Client need not provide cert.
 *      SSL_VERIFY_FAIL_IF_NO_PEER_CERT     Fail if client does not provide cert. Must be used with SSL_VERIFY_PEER.
 *      SSL_VERIFY_CLIENT_ONCE              Only request client cert once.  Must be used with SSL_VERIFY_PEER.
 *
 * OpenSSL will call verify_callback during the certificate verification process.
 * It will only hit if SSL_VERIFY_PEER is set.
 *
 * verify_callback's full signature is:
 *      int (*verify_callback)(int preverify_ok, X509_STORE_CTX *x509_ctx)
 *  preverify_ok is the current status of the OpenSSL verification: 1 for success, 0 for failure.
 *  x509_ctx is the complete X509 certificate chain context.
 *  The return value will alter/override OpenSSL's verification result: 1 for success, 0 for failure.
 *
 * verify_callback can be NULL, in which case the value of OpenSSL verification is used.
 *
 * Returns a pointer to the SSL context on success, NULL on error.
 * The caller is responsible for freeing the SSL context using SSL_CTX_free().
 */
SSL_CTX *initialize_ssl_context(int verify_options);
SSL_CTX *initialize_ssl_context2(int verify_options, int (*verify_callback)(int, X509_STORE_CTX *));

void cdssl_print_x509_name(X509_NAME *name);
/*
 * Free all SSL context resources... usually.
 *
 * Decreases reference counter to context struct.
 * Frees when the counter reaches 0.
 */
void destroy_ssl_context(SSL_CTX *ctx);

/*
 * Create handle for an individual SSL connection.
 *
 * The SSL connection/TLS handshake takes place over the provided TCP connection
 * (I think it must already be connected?).
 *
 * Returns a pointer to an SSL connection on success, NULL on failure.
 */
SSL *initialize_ssl_connection(SSL_CTX *ctx, int socket_fd);

/*
 * Free all SSL connection resources... usually.
 *
 * Decreases reference counter to connection struct.
 * Frees when the counter reaches 0.
 */
void destroy_ssl_connection(SSL *ssl);


/*
 * Configure the Common Name check that OpenSSL perform when it receives a peer certificate.
 * A Common Name check will *not* be performed unless this function is called.
 * Must be called after SSL connection is initialized but before it is connected.
 *
 * Available flags are listed in <openssl/x509v3.h>
 * or see https://www.openssl.org/docs/man1.0.2/crypto/X509_check_host.html:
 *      Always check subject name for host match even if subject alt names present
 *      # define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    0x1
 *
 *      Disable wildcard matching for dnsName fields and common name.
 *      # define X509_CHECK_FLAG_NO_WILDCARDS    0x2
 *
 *      Wildcards must not match a partial label.
 *      # define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
 *
 *      Allow (non-partial) wildcards to match multiple labels.
 *      # define X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8
 *
 *      Constraint verifier subdomain patterns to match a single labels.
 *      # define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10
 *
 *      Never check the subject CN
 *      # define X509_CHECK_FLAG_NEVER_CHECK_SUBJECT    0x20
 *
 *      Match reference identifiers starting with "." to any sub-domain.
 *      This is a non-public flag, turned on implicitly when the subject
 *      reference identity is a DNS name.
 *      # define _X509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000
 *
 * The documentation states that these flags are found in <openssl/x509.h>
 * I found then in <openssl/x509v3.h>
 *
 * Returns 0 on success, -1 on failure.
 */
int cdssl_verify_common_name(SSL *ssl, const char *common_name, unsigned int flags);

/*
 * Connect to a TLS server and perform the TLS handshake.
 *
 * Returns:
 *      1 if handshake succeeded
 *      0 if handshake failed according to spec
 *      < 0 on error
 */
int ssl_connect(SSL *ssl);

/*
 * Accept a connection request from a TLS client and respond to a TLS handhake.
 *
 * Blocking read - waits until a connection request is received.
 *
 * Returns:
 *      1 if handshake succeeded
 *      0 if handshake failed according to spec
 *      < 0 on error
 */
int ssl_accept(SSL *ssl);

/*
 * Explicitly check server certificate
 *
 * Extra checks are required for OpenSSL 1.02 or below:
 *      Get the server's certificate
 *      Verify that the handshake was successful
 *      Verify that the common name matches the host name
 * See https://wiki.openssl.org/index.php/SSL/TLS_Client#Server_Certificate
 */
int check_server_cert(SSL *ssl, const char *host);

/*
 * Load file containe list of trusted Certificate Authorities.
 *
 * Returns 0 on success, -1 on failure.
 */
int load_ca_list(SSL_CTX *ctx, const char *ca_list_file);

/*
 * Load certificate chain file and corresponding private key file, then verify the private key.
 *
 * TODO Should enter passphrase for key?
 * Returns 0 on success, -1 on failure.
 */
int load_certificate_and_key(SSL_CTX *ctx, const char *cert_file, const char *key_file);

/*
 * Set Diffie-Hellman parameters in SSL Context.
 *
 * Returns 0 on success, -1 on failure.
 */
int load_dh_params(SSL_CTX *ctx, char *file);

// Pull these private again?
void print_error(char *string);
int ssl_print_error(char *string);

#endif

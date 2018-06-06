#ifndef CDSSL_INCLUDED
#define CDSSL_INCLUDED

// Technically we should hide this, but wrapping the SSL_CTX struct is more effort than this demo is worth.
#include <openssl/ssl.h>

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
 * Returns a pointer to the SSL context on success, NULL on error.
 * The caller is responsible for freeing the SSL context using SSL_CTX_free().
 */
SSL_CTX *initialize_ssl_context(int verify_options);

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
 * Perform the TLS handshake.
 *
 * Returns:
 *      1 if handshake succeeded
 *      0 if handshake failed according to spec
 *      < 0 on error
 */
int ssl_connect(SSL *ssl);

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


// Pull these private again?
void print_error(char *string);
int ssl_print_error(char *string);

#endif

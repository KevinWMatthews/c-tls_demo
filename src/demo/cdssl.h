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
 * Returns a pointer to the SSL context on success, NULL on error.
 */
SSL_CTX *initialize_ssl_context(void);

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

// Pull these private again?
void print_error(char *string);
int ssl_print_error(char *string);

#endif

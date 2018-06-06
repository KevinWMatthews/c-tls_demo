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
 * Initialize and configure the SSL context.
 *
 * This context applies to all SSL connections made in the the program.
 *
 * Returns a pointer to the SSL context on success, NULL on error.
 */
SSL_CTX *initialize_ssl_context(void);


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
 * Perform the TLS handshake.
 *
 * Returns:
 *      1 if handshake succeeded
 *      0 if handshake failed according to spec
 *      < 0 on error
 */
int ssl_connect(SSL *ssl);

// Pull these private again?
void print_error(char *string);
int ssl_print_error(char *string);

#endif

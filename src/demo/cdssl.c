#include "cdssl.h"
#include <openssl/err.h>


// Handle to SSL Basic IO context for printing errors.
static BIO *bio_err;

/*
 * Print custom user message to OpenSSL's error IO.
 *
 * Use for printing errors that occur in user code.
 */
//TODO add varargs?
void print_error(char *string)
{
    // Print user's string to BIO file handle
    BIO_printf(bio_err, "%s", string);
}

/*
 * Print custom user message and OpenSSL's error message to SSL Basic IO handle.
 *
 * Use for printing details of errors that stem from the SSL library.
 */
int ssl_print_error(char *string)
{
    print_error(string);
    ERR_print_errors(bio_err);              // Print information on SSL library error
}


void initialize_ssl_library(void)
{
    // add_all_algorithms?
    SSL_library_init();

    // Add SSL Basic IO construct for error handling.
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);      // I don't know if/how to free this.
}

SSL_CTX *initialize_ssl_context(void)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx = NULL;

    method = SSLv23_method();       // Can this fail?

    /*
     * SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
     *
     * Returns pointer to SSL_CTX struct on success, NULL on failure.
     */
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        ssl_print_error("Failed to create SSL context\n");
        return NULL;
    }

    /*
     * https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_verify.html
     * void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX *));
     *
     * Callback can be null.
     *
     * Valid modes for a client are:
     *      SSL_VERIFY_NONE     Continue if server does not provide cert
     *      SSL_VERIFY_PEER     Fail if server does not provide cert
     */
    // Could also set the verify parameters for a specific SSL connection.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /*
     * void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
     */
    // Should we do this?

    return ctx;
}

/*
 * Before we perform the SSL/TLS handshake, we must connect SSL's network layer using SSL_set_fd() or SSL_set_bio().
 */
SSL *initialize_ssl_connection(SSL_CTX *ctx, int socket_fd)
{
    SSL *ssl = NULL;
    BIO *socket_bio = NULL;     // Basic IO for socket

    /*
     * SSL *SSL_new(SSL_CTX *ctx);
     *
     * Returns a pointer on success and NULL on failure.
     */
    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        ssl_print_error("Error creating SSL context\n");
        return NULL;
    }

    /*
     * BIO *BIO_new_socket(int sock, int close_flag);
     *
     * If set, close_flag will automatically close the socket when the bio is freed. Could be nice?
     * The BIO is automatically freed when the corresponding SSL object is free. You'd better associate it with an SSL object?
     * Returns a pointer on success and NULL on failure.
     */
    socket_bio = BIO_new_socket(socket_fd, BIO_NOCLOSE);
    if (socket_bio == NULL)
    {
        ssl_print_error("Failed to create BIO for SSL socket\n");
        SSL_free(ssl);
        return NULL;
    }

    /*
     * void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
     *
     * Set read and write Basic IO's for the SSL connection.
     * Can not fail.
     */
    SSL_set_bio(ssl, socket_bio, socket_bio);

    return ssl;
}

int ssl_connect(SSL *ssl)
{
    int ret;

    /*
     * int SSL_connect(SSL *ssl);
     *
     * SSL_connect() initiates the TLS/SSL handshake with a server.
     * The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
     *
     * Return values:
     *      1 on success
     *      0 if not successful but according to spec
     *      < 0 on error
     */
    ret = SSL_connect(ssl);
    if ( ret <= 0 )
    {
        ssl_print_error("Failed to complete TLS handshake\n");
    }
    return ret;
}


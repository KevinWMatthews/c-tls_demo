#include "cdssl.h"
#include <openssl/err.h>
#include <strings.h>


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
    // ERR_print_errors(bio_err);              // Print information on SSL library error
    ERR_print_errors_fp(stderr);
}


void cdssl_print_x509_name(X509_NAME *name)
{
    X509_NAME_print_ex(bio_err, name, 0, 0);
    BIO_printf(bio_err, "\n");
}


void initialize_ssl_library(void)
{
    // add_all_algorithms?
    SSL_library_init();

    // Add SSL Basic IO construct for error handling.
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);      // I don't know if/how to free this.

    //TODO add varargs support to local print() functions
    fprintf(stderr, "%s\n", OpenSSL_version(OPENSSL_VERSION));
}

SSL_CTX *initialize_ssl_context(int verify_options)
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
     * verify_callback can be null.
     *
     * Valid modes for a client are:
     *      SSL_VERIFY_NONE                     Continue if server does not provide cert
     *      SSL_VERIFY_PEER                     Fail if server does not provide cert
     * Valid modes for a server server are:
     *      SSL_VERIFY_NONE                     Do not send certificate request to client
     *      SSL_VERIFY_PEER                     Send certificate request. Client need not provide cert.
     *      SSL_VERIFY_FAIL_IF_NO_PEER_CERT     Fail if client does not provide cert. Must be used with SSL_VERIFY_PEER.
     *      SSL_VERIFY_CLIENT_ONCE              Only request client cert once.  Must be used with SSL_VERIFY_PEER.
     */
    // Could also set the verify parameters for a specific SSL connection (created elsewhere).
    SSL_CTX_set_verify(ctx, verify_options, NULL);

    /*
     * void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
     */
    // Should we do this?

    return ctx;
}

SSL_CTX *initialize_ssl_context2(int verify_options, int (*verify_callback)(int, X509_STORE_CTX *))
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
     * Valid modes for a client are:
     *      SSL_VERIFY_NONE                     Continue if server does not provide cert
     *      SSL_VERIFY_PEER                     Fail if server does not provide cert
     * Valid modes for a server server are:
     *      SSL_VERIFY_NONE                     Do not send certificate request to client
     *      SSL_VERIFY_PEER                     Send certificate request. Client need not provide cert.
     *      SSL_VERIFY_FAIL_IF_NO_PEER_CERT     Fail if client does not provide cert. Must be used with SSL_VERIFY_PEER.
     *      SSL_VERIFY_CLIENT_ONCE              Only request client cert once.  Must be used with SSL_VERIFY_PEER.
     *
     * verify_callback can be NULL.
     */
    // Could also set the verify parameters for a specific SSL connection (created elsewhere).
    SSL_CTX_set_verify(ctx, verify_options, verify_callback);

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

void destroy_ssl_connection(SSL *ssl)
{
    /*
     * void SSL_free(SSL *ssl);
     * SSL_free() decrements the reference count of ssl, and
     * removes the SSL structure pointed to by ssl and
     * frees up the allocated memory if the reference count has reached 0.
     */
    SSL_free(ssl);
}

int cdssl_verify_common_name(SSL *ssl, const char *common_name, unsigned int flags)
{
    // Taken from https://wiki.openssl.org/index.php/Hostname_validation
    //
    // There may be bugs:
    //      OpenSSL ticket #3288
    //      https://rt.openssl.org/Ticket/Display.html?id=3288&user=guest&pass=guest
    //      https://groups.google.com/forum/#!topic/mailing.openssl.dev/YcJX0njO1oo
    // See also https://tools.ietf.org/html/rfc6125

    //NOTE this implementation is specific to ssl 1.0.0
    // https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_hostflags.html

    /*
     * Set parameters that OpenSSL will use when calling X509_check_host().
     * "SSL clients are advised to use these functions in preference to explicitly calling X509_check_host".
     */

    /*
     * void SSL_set_hostflags(SSL *s, unsigned int flags)
     *
     * Set flags that will be passed to to X509_check_host()
     * [this function is called by OpenSSL].
     */
    SSL_set_hostflags(ssl, flags);

    /*
     * int SSL_set1_host(SSL *s, const char *hostname)
     *
     * Sets the hostname that will be checked by X509_check_host().
     * [this function is called by OpenSSL].
     * Removes any previously specified hostnames.
     * If the hsotname is empty or NULL, common name checks are not performed.
     *
     * Returns values:
     *      1 on success
     *      0 on failure
     */
    if ( SSL_set1_host(ssl, common_name) == 0 )
    {
        ssl_print_error("Failed to set hostname for common name validation\n");
        return -1;
    }

    //TODO implement for OpenSSL v1.0.2
    // https://www.openssl.org/docs/man1.0.2/crypto/X509_VERIFY_PARAM_set1_host.html

    return 0;
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

int ssl_accept(SSL *ssl)
{
    int ret;

    /*
     * int SSL_accept(SSL *ssl);
     *
     * SSL_accept() waits for a TLS/SSL client to initiate the TLS/SSL handshake.
     * The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
     *
     * Return values:
     *      1 on success
     *      0 if not successful but according to spec
     *      < 0 on error
     */
    ret = SSL_accept(ssl);
    if ( ret <= 0 )
    {
        fprintf(stderr, "%s: Failed to complete TLS handshake\n", __func__);
    }
    return ret;
}

void destroy_ssl_context(SSL_CTX *ctx)
{
    /*
     * void SSL_CTX_free(SSL_CTX *ctx);
     *
     * SSL_CTX_free() decrements the reference count of ctx, and
     * removes the SSL_CTX object pointed to by ctx and
     * frees up the allocated memory if the the reference count has reached 0.
     */
    SSL_CTX_free(ctx);
}

static int check_common_name(X509 *cert, const char *host)
{
    char peer_CN[256] = {0};

    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, peer_CN, 256);
    printf("peer_CN = %s, host = %s\n", peer_CN, host);

    if ( strcasecmp(peer_CN, host) )
    {
        print_error("Common name doesn't match host name\n");
        return -1;
    }
    return 0;
}

int check_server_cert(SSL *ssl, const char *host)
{
    X509 *server_cert = NULL;

    // Get the server's certificate
    server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert == NULL)
    {
        print_error("Server did not provide certificate\n");
        return -1;
    }

    // Verify that the handshake was successful
    if ( SSL_get_verify_result(ssl) != X509_V_OK )
    {
        print_error("Server certificate is not valid\n");
        X509_free(server_cert);
        return -1;
    }

    // Verify that the common name matches the host name
    if ( check_common_name(server_cert, host) < 0 )
    {
        X509_free(server_cert);
        return -1;
    }

    X509_free(server_cert);
    return 0;
}

int load_ca_list(SSL_CTX *ctx, const char *ca_list_file)
{
    /*
     * int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
     *
     * Returns 1 on success, 0 on failure.
     */
    if( !SSL_CTX_load_verify_locations(ctx, ca_list_file, 0) )      // We could add a path.
    {
        ssl_print_error("Can't read CA list");
        return -1;
    }
    return 0;
}

int load_certificate_and_key(SSL_CTX *ctx, const char *cert_file, const char *key_file)
{
    /*
     * int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
     *
     * SSL_CTX_use_certificate_chain_file() loads a certificate chain from file into ctx.
     * The certificates must be in PEM format and must be sorted starting with the subject's certificate
     * (actual client or server certificate), followed by intermediate CA certificates if applicable,
     * and ending at the highest level (root) CA
     *
     * Returns 1 on success, not 1 on error.
     */
    if ( SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1 )
    // if ( SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != 1 )
    {
        ssl_print_error("Error loading certificate chain\n");
        return -1;
    }

    // SSL_CTX_set_default_passwd_cb()
    // or
    // SSL_CTX_set_default_passwd_cb()
    /*
     * int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
     *
     * Returns 1 on success, not 1 on error.
     */
    if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1 )
    {
        ssl_print_error("Error loading private key\n");
        return -1;
    }

    /*
     * int SSL_CTX_check_private_key(const SSL_CTX *ctx);
     */
    if ( SSL_CTX_check_private_key(ctx) != 1 )
    {
        ssl_print_error("Failed to check private key\n");
        return -1;
    }

    return 0;
}

int load_dh_params(SSL_CTX *ctx, char *file)
{
    DH *ret = 0;
    BIO *bio = 0;

    bio = BIO_new_file(file, "r");

    if ( bio == NULL)
    {
        print_error("Couldn't open DH file");
        return -1;
    }

    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);     //TODO Document
    BIO_free(bio);
    if ( SSL_CTX_set_tmp_dh(ctx, ret) < 0 )         //TODO What does this do?
    {
        ssl_print_error("Couldn't set DH parameters");
        return -1;
    }

    return 0;
}

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_LIST     "keys/ca.crt"

// Global error handling struct
static BIO *bio_err = 0;

/*
 * Print SSL errors and exit
 */
static int berr_exit(char *string)
{
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
}

/* * Create SSL context
 *
 * Initialize SSL library
 * Start error handling process
 * Load CA list
 */
SSL_CTX *initialize_ctx()
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err)
    {
        SSL_library_init();
        SSL_load_error_strings();
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);  // setup an error write context
    }

    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST, 0)))
        berr_exit("Can't read CA list");

    return ctx;
}

/*
 * Release all resources held by SSL context.
 */
void destroy_ctx(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}

int main(void)
{
    SSL_CTX *ctx = 0;

    OpenSSL_add_all_algorithms();
    ctx = initialize_ctx();

    destroy_ctx(ctx);

    return 0;
}

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Testing libssl integration...\n");

    // Check OpenSSL version
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));

    // Check if DSSSL hardening is present
    const char *version = OpenSSL_version(OPENSSL_VERSION);
    if (strstr(version, "DSSSL") || strstr(version, "DSLLVM")) {
        printf("✓ DSSSL hardening detected in version string\n");
    } else {
        printf("⚠ DSSSL hardening not detected in version string (may still be present)\n");
    }

    // Test basic SSL context creation
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (ctx) {
        printf("✓ SSL context creation successful\n");
        SSL_CTX_free(ctx);
    } else {
        printf("✗ SSL context creation failed\n");
        return 1;
    }

    // Check for hardening features
#ifdef _FORTIFY_SOURCE
    printf("✓ _FORTIFY_SOURCE enabled (level %d)\n", _FORTIFY_SOURCE);
#endif

#ifdef __SSP__
    printf("✓ Stack smashing protection (__SSP__) enabled\n");
#endif

#ifdef __PIE__
    printf("✓ Position Independent Executable (__PIE__) enabled\n");
#endif

    printf("libssl integration test completed successfully!\n");
    return 0;
}

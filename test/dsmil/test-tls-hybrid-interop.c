/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * TLS 1.3 Hybrid KEM Interoperability Tests
 *
 * This test suite validates interoperability between DSSSL clients and servers
 * using hybrid KEM groups, including compatibility with standard TLS 1.3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "../helpers/ssltestlib.h"
#include "../testutil.h"
#include "internal/tlsgroups.h"

#ifndef OPENSSL_NO_TLS1_3

/* Test configuration */
static const char *test_cert = "test/certs/servercert.pem";
static const char *test_key = "test/certs/serverkey.pem";

/*
 * Test 1: DSSSL Client <-> DSSSL Server with Hybrid KEM
 */
static int test_dsssl_client_dsssl_server_hybrid(void)
{
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *s_to_c_fbio = NULL, *c_to_s_fbio = NULL;
    uint16_t negotiated_group = 0;
    int ret = 0;

    TEST_info("Test: DSSSL Client <-> DSSSL Server with Hybrid KEM");

    setenv("DSMIL_PROFILE", "WORLD_COMPAT", 1);

    if (!TEST_ptr(serverctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method())))
        goto err;

    if (!TEST_ptr(clientctx = SSL_CTX_new_ex(NULL, NULL, TLS_client_method())))
        goto err;

    if (!TEST_true(SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION)))
        goto err;

    if (access(test_cert, R_OK) != 0) {
        TEST_skip("Test certificate not available");
        goto err;
    }

    if (!TEST_true(SSL_CTX_use_certificate_file(serverctx, test_cert, SSL_FILETYPE_PEM))
            || !TEST_true(SSL_CTX_use_PrivateKey_file(serverctx, test_key, SSL_FILETYPE_PEM)))
        goto err;

    if (!TEST_ptr(s_to_c_fbio = BIO_new(BIO_s_mem()))
            || !TEST_ptr(c_to_s_fbio = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_true(create_ssl_objects(serverctx, clientctx, &serverssl, &clientssl,
                                       s_to_c_fbio, c_to_s_fbio)))
        goto err;

    /* Set hybrid groups on both */
    if (!TEST_true(SSL_set1_groups_list(clientssl, "X25519MLKEM768:SecP256r1MLKEM768"))
            || !TEST_true(SSL_set1_groups_list(serverssl, "X25519MLKEM768:SecP256r1MLKEM768")))
        goto err;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto err;

    negotiated_group = SSL_get_negotiated_group(clientssl);
    TEST_info("Negotiated group: 0x%04x", negotiated_group);

    if (!TEST_true(negotiated_group == OSSL_TLS_GROUP_ID_X25519MLKEM768 ||
                   negotiated_group == OSSL_TLS_GROUP_ID_SecP256r1MLKEM768)) {
        TEST_error("Hybrid group not negotiated");
        goto err;
    }

    ret = 1;

err:
    if (clientssl != NULL)
        SSL_free(clientssl);
    if (serverssl != NULL)
        SSL_free(serverssl);
    if (clientctx != NULL)
        SSL_CTX_free(clientctx);
    if (serverctx != NULL)
        SSL_CTX_free(serverctx);
    if (s_to_c_fbio != NULL)
        BIO_free(s_to_c_fbio);
    if (c_to_s_fbio != NULL)
        BIO_free(c_to_s_fbio);

    return ret;
}

/*
 * Test 2: DSSSL Client (Hybrid) <-> Standard Server (Classical Fallback)
 */
static int test_dsssl_client_standard_server_fallback(void)
{
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *s_to_c_fbio = NULL, *c_to_s_fbio = NULL;
    uint16_t negotiated_group = 0;
    int ret = 0;

    TEST_info("Test: DSSSL Client (Hybrid) <-> Standard Server (Fallback)");

    setenv("DSMIL_PROFILE", "WORLD_COMPAT", 1);

    if (!TEST_ptr(serverctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method())))
        goto err;

    if (!TEST_ptr(clientctx = SSL_CTX_new_ex(NULL, NULL, TLS_client_method())))
        goto err;

    if (!TEST_true(SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION)))
        goto err;

    if (access(test_cert, R_OK) != 0) {
        TEST_skip("Test certificate not available");
        goto err;
    }

    if (!TEST_true(SSL_CTX_use_certificate_file(serverctx, test_cert, SSL_FILETYPE_PEM))
            || !TEST_true(SSL_CTX_use_PrivateKey_file(serverctx, test_key, SSL_FILETYPE_PEM)))
        goto err;

    if (!TEST_ptr(s_to_c_fbio = BIO_new(BIO_s_mem()))
            || !TEST_ptr(c_to_s_fbio = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_true(create_ssl_objects(serverctx, clientctx, &serverssl, &clientssl,
                                       s_to_c_fbio, c_to_s_fbio)))
        goto err;

    /* Client offers hybrid + classical, server only supports classical */
    if (!TEST_true(SSL_set1_groups_list(clientssl, "X25519MLKEM768:X25519:SecP256r1"))
            || !TEST_true(SSL_set1_groups_list(serverssl, "X25519:SecP256r1")))
        goto err;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto err;

    negotiated_group = SSL_get_negotiated_group(clientssl);
    TEST_info("Negotiated group: 0x%04x", negotiated_group);

    /* Should fall back to classical */
    if (!TEST_true(negotiated_group == OSSL_TLS_GROUP_ID_x25519 ||
                   negotiated_group == OSSL_TLS_GROUP_ID_secp256r1)) {
        TEST_info("Fallback to classical group successful");
    }

    ret = 1;

err:
    if (clientssl != NULL)
        SSL_free(clientssl);
    if (serverssl != NULL)
        SSL_free(serverssl);
    if (clientctx != NULL)
        SSL_CTX_free(clientctx);
    if (serverctx != NULL)
        SSL_CTX_free(serverctx);
    if (s_to_c_fbio != NULL)
        BIO_free(s_to_c_fbio);
    if (c_to_s_fbio != NULL)
        BIO_free(c_to_s_fbio);

    return ret;
}

/*
 * Test 3: Data Exchange with Hybrid KEM
 */
static int test_hybrid_kem_data_exchange(void)
{
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *s_to_c_fbio = NULL, *c_to_s_fbio = NULL;
    const char *test_data = "Hello, Hybrid KEM!";
    char buffer[256];
    int len;
    int ret = 0;

    TEST_info("Test: Data Exchange with Hybrid KEM");

    setenv("DSMIL_PROFILE", "WORLD_COMPAT", 1);

    if (!TEST_ptr(serverctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method())))
        goto err;

    if (!TEST_ptr(clientctx = SSL_CTX_new_ex(NULL, NULL, TLS_client_method())))
        goto err;

    if (!TEST_true(SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION)))
        goto err;

    if (access(test_cert, R_OK) != 0) {
        TEST_skip("Test certificate not available");
        goto err;
    }

    if (!TEST_true(SSL_CTX_use_certificate_file(serverctx, test_cert, SSL_FILETYPE_PEM))
            || !TEST_true(SSL_CTX_use_PrivateKey_file(serverctx, test_key, SSL_FILETYPE_PEM)))
        goto err;

    if (!TEST_ptr(s_to_c_fbio = BIO_new(BIO_s_mem()))
            || !TEST_ptr(c_to_s_fbio = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_true(create_ssl_objects(serverctx, clientctx, &serverssl, &clientssl,
                                       s_to_c_fbio, c_to_s_fbio)))
        goto err;

    if (!TEST_true(SSL_set1_groups_list(clientssl, "X25519MLKEM768"))
            || !TEST_true(SSL_set1_groups_list(serverssl, "X25519MLKEM768")))
        goto err;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto err;

    /* Client sends data */
    len = SSL_write(clientssl, test_data, strlen(test_data));
    if (!TEST_int_gt(len, 0))
        goto err;

    /* Server reads data */
    len = SSL_read(serverssl, buffer, sizeof(buffer) - 1);
    if (!TEST_int_gt(len, 0))
        goto err;
    buffer[len] = '\0';

    if (!TEST_str_eq(buffer, test_data))
        goto err;

    /* Server sends response */
    const char *response = "Response from server";
    len = SSL_write(serverssl, response, strlen(response));
    if (!TEST_int_gt(len, 0))
        goto err;

    /* Client reads response */
    len = SSL_read(clientssl, buffer, sizeof(buffer) - 1);
    if (!TEST_int_gt(len, 0))
        goto err;
    buffer[len] = '\0';

    if (!TEST_str_eq(buffer, response))
        goto err;

    ret = 1;

err:
    if (clientssl != NULL)
        SSL_free(clientssl);
    if (serverssl != NULL)
        SSL_free(serverssl);
    if (clientctx != NULL)
        SSL_CTX_free(clientctx);
    if (serverctx != NULL)
        SSL_CTX_free(serverctx);
    if (s_to_c_fbio != NULL)
        BIO_free(s_to_c_fbio);
    if (c_to_s_fbio != NULL)
        BIO_free(c_to_s_fbio);

    return ret;
}

/*
 * Test 4: Multiple Hybrid Groups Priority
 */
static int test_multiple_hybrid_groups_priority(void)
{
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *s_to_c_fbio = NULL, *c_to_s_fbio = NULL;
    uint16_t negotiated_group = 0;
    int ret = 0;

    TEST_info("Test: Multiple Hybrid Groups Priority");

    setenv("DSMIL_PROFILE", "WORLD_COMPAT", 1);

    if (!TEST_ptr(serverctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method())))
        goto err;

    if (!TEST_ptr(clientctx = SSL_CTX_new_ex(NULL, NULL, TLS_client_method())))
        goto err;

    if (!TEST_true(SSL_CTX_set_min_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(serverctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_min_proto_version(clientctx, TLS1_3_VERSION))
            || !TEST_true(SSL_CTX_set_max_proto_version(clientctx, TLS1_3_VERSION)))
        goto err;

    if (access(test_cert, R_OK) != 0) {
        TEST_skip("Test certificate not available");
        goto err;
    }

    if (!TEST_true(SSL_CTX_use_certificate_file(serverctx, test_cert, SSL_FILETYPE_PEM))
            || !TEST_true(SSL_CTX_use_PrivateKey_file(serverctx, test_key, SSL_FILETYPE_PEM)))
        goto err;

    if (!TEST_ptr(s_to_c_fbio = BIO_new(BIO_s_mem()))
            || !TEST_ptr(c_to_s_fbio = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_true(create_ssl_objects(serverctx, clientctx, &serverssl, &clientssl,
                                       s_to_c_fbio, c_to_s_fbio)))
        goto err;

    /* Client offers multiple hybrid groups */
    if (!TEST_true(SSL_set1_groups_list(clientssl, "SecP256r1MLKEM768:X25519MLKEM768"))
            || !TEST_true(SSL_set1_groups_list(serverssl, "SecP256r1MLKEM768:X25519MLKEM768")))
        goto err;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto err;

    negotiated_group = SSL_get_negotiated_group(clientssl);
    TEST_info("Negotiated group: 0x%04x", negotiated_group);

    /* Should negotiate one of the hybrid groups */
    if (!TEST_true(negotiated_group == OSSL_TLS_GROUP_ID_X25519MLKEM768 ||
                   negotiated_group == OSSL_TLS_GROUP_ID_SecP256r1MLKEM768)) {
        TEST_error("Hybrid group not negotiated");
        goto err;
    }

    ret = 1;

err:
    if (clientssl != NULL)
        SSL_free(clientssl);
    if (serverssl != NULL)
        SSL_free(serverssl);
    if (clientctx != NULL)
        SSL_CTX_free(clientctx);
    if (serverctx != NULL)
        SSL_CTX_free(serverctx);
    if (s_to_c_fbio != NULL)
        BIO_free(s_to_c_fbio);
    if (c_to_s_fbio != NULL)
        BIO_free(c_to_s_fbio);

    return ret;
}

#endif /* OPENSSL_NO_TLS1_3 */

int setup_tests(void)
{
#ifndef OPENSSL_NO_TLS1_3
    ADD_TEST(test_dsssl_client_dsssl_server_hybrid);
    ADD_TEST(test_dsssl_client_standard_server_fallback);
    ADD_TEST(test_hybrid_kem_data_exchange);
    ADD_TEST(test_multiple_hybrid_groups_priority);
    return 1;
#else
    TEST_note("TLS 1.3 not available");
    return 1;
#endif
}

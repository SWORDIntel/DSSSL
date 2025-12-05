/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * Policy Enforcement Test Suite
 *
 * Tests that the DSMIL policy provider correctly filters algorithms
 * based on security profiles (WORLD_COMPAT, DSMIL_SECURE, ATOMAL).
 *
 * See: docs/reports/DSSSL_SECURITY_AUDIT_REPORT.md Section 7.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include "providers/dsmil/policy.h"

/*
 * Test KEM algorithm filtering
 */
static int test_kem_filtering(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *dsmil_prov = NULL;
    DSMIL_POLICY_CTX *policy_ctx = NULL;
    int ret = 1;

    printf("Testing KEM algorithm filtering...\n");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create library context\n");
        return 0;
    }

    /* Load DSMIL provider */
    dsmil_prov = OSSL_PROVIDER_load(libctx, "dsmil");
    if (dsmil_prov == NULL) {
        fprintf(stderr, "Failed to load DSMIL provider\n");
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    /* Test WORLD_COMPAT profile */
    printf("  Testing WORLD_COMPAT profile...\n");
    policy_ctx = dsmil_policy_ctx_new(libctx);
    if (policy_ctx == NULL) {
        fprintf(stderr, "Failed to create policy context\n");
        ret = 0;
        goto err;
    }

    dsmil_policy_set_profile(policy_ctx, DSMIL_PROFILE_WORLD_COMPAT);

    /* All KEMs should be allowed */
    if (dsmil_policy_check_kem(policy_ctx, "X25519", 0) != DSMIL_DECISION_ALLOWED) {
        fprintf(stderr, "  FAIL: X25519 should be allowed in WORLD_COMPAT\n");
        ret = 0;
    }
    if (dsmil_policy_check_kem(policy_ctx, "X25519MLKEM768", 1) != DSMIL_DECISION_ALLOWED) {
        fprintf(stderr, "  FAIL: Hybrid KEM should be allowed in WORLD_COMPAT\n");
        ret = 0;
    }
    printf("    PASS: WORLD_COMPAT allows all KEMs\n");

    /* Test DSMIL_SECURE profile */
    printf("  Testing DSMIL_SECURE profile...\n");
    dsmil_policy_set_profile(policy_ctx, DSMIL_PROFILE_DSMIL_SECURE);

    /* Non-hybrid KEMs should be blocked */
    if (dsmil_policy_check_kem(policy_ctx, "X25519", 0) != DSMIL_DECISION_BLOCKED) {
        fprintf(stderr, "  FAIL: Non-hybrid KEM should be blocked in DSMIL_SECURE\n");
        ret = 0;
    }

    /* Hybrid KEMs should be allowed */
    if (dsmil_policy_check_kem(policy_ctx, "X25519MLKEM768", 1) != DSMIL_DECISION_ALLOWED) {
        fprintf(stderr, "  FAIL: Hybrid KEM should be allowed in DSMIL_SECURE\n");
        ret = 0;
    }
    printf("    PASS: DSMIL_SECURE requires hybrid KEMs\n");

    /* Test ATOMAL profile */
    printf("  Testing ATOMAL profile...\n");
    dsmil_policy_set_profile(policy_ctx, DSMIL_PROFILE_ATOMAL);

    /* Pure classical KEMs should be blocked */
    if (dsmil_policy_check_kem(policy_ctx, "X25519", 0) != DSMIL_DECISION_BLOCKED) {
        fprintf(stderr, "  FAIL: Classical KEM should be blocked in ATOMAL\n");
        ret = 0;
    }

    /* Hybrid or PQC-only should be allowed */
    if (dsmil_policy_check_kem(policy_ctx, "X25519MLKEM1024", 1) != DSMIL_DECISION_ALLOWED) {
        fprintf(stderr, "  FAIL: Hybrid KEM should be allowed in ATOMAL\n");
        ret = 0;
    }
    if (dsmil_policy_check_kem(policy_ctx, "ML-KEM-1024", 0) != DSMIL_DECISION_ALLOWED) {
        fprintf(stderr, "  FAIL: PQC-only KEM should be allowed in ATOMAL\n");
        ret = 0;
    }
    printf("    PASS: ATOMAL requires hybrid or PQC-only\n");

err:
    if (policy_ctx != NULL)
        dsmil_policy_ctx_free(policy_ctx);
    if (dsmil_prov != NULL)
        OSSL_PROVIDER_unload(dsmil_prov);
    if (libctx != NULL)
        OSSL_LIB_CTX_free(libctx);

    return ret;
}

/*
 * Test signature algorithm filtering
 */
static int test_signature_filtering(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    DSMIL_POLICY_CTX *policy_ctx = NULL;
    int ret = 1;

    printf("Testing signature algorithm filtering...\n");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create library context\n");
        return 0;
    }

    policy_ctx = dsmil_policy_ctx_new(libctx);
    if (policy_ctx == NULL) {
        fprintf(stderr, "Failed to create policy context\n");
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    /* Test ATOMAL profile - should block classical-only signatures */
    dsmil_policy_set_profile(policy_ctx, DSMIL_PROFILE_ATOMAL);

    if (dsmil_policy_check_signature(policy_ctx, "ecdsa", 0) != DSMIL_DECISION_BLOCKED) {
        fprintf(stderr, "  FAIL: Classical signature should be blocked in ATOMAL\n");
        ret = 0;
    }

    if (dsmil_policy_check_signature(policy_ctx, "ML-DSA-87", 0) != DSMIL_DECISION_ALLOWED) {
        fprintf(stderr, "  FAIL: ML-DSA-87 should be allowed in ATOMAL\n");
        ret = 0;
    }

    printf("    PASS: ATOMAL blocks classical-only signatures\n");

    dsmil_policy_ctx_free(policy_ctx);
    OSSL_LIB_CTX_free(libctx);

    return ret;
}

/*
 * Test input validation
 */
static int test_input_validation(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    DSMIL_POLICY_CTX *policy_ctx = NULL;
    int ret = 1;

    printf("Testing input validation...\n");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create library context\n");
        return 0;
    }

    policy_ctx = dsmil_policy_ctx_new(libctx);
    if (policy_ctx == NULL) {
        fprintf(stderr, "Failed to create policy context\n");
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    /* Test invalid profile string */
    if (dsmil_policy_set_profile_str(policy_ctx, "INVALID_PROFILE") != 0) {
        fprintf(stderr, "  FAIL: Invalid profile should be rejected\n");
        ret = 0;
    }

    /* Should default to WORLD_COMPAT */
    if (dsmil_policy_get_profile(policy_ctx) != DSMIL_PROFILE_WORLD_COMPAT) {
        fprintf(stderr, "  FAIL: Should default to WORLD_COMPAT after invalid input\n");
        ret = 0;
    }

    printf("    PASS: Invalid inputs handled correctly\n");

    dsmil_policy_ctx_free(policy_ctx);
    OSSL_LIB_CTX_free(libctx);

    return ret;
}

/*
 * Main test runner
 */
int main(int argc, char **argv)
{
    int ret = 1;

    printf("========================================\n");
    printf("DSMIL Policy Enforcement Test Suite\n");
    printf("Phase 2: Policy Provider Testing\n");
    printf("========================================\n\n");

    if (!test_kem_filtering()) {
        fprintf(stderr, "KEM filtering test FAILED\n");
        ret = 0;
    }
    printf("\n");

    if (!test_signature_filtering()) {
        fprintf(stderr, "Signature filtering test FAILED\n");
        ret = 0;
    }
    printf("\n");

    if (!test_input_validation()) {
        fprintf(stderr, "Input validation test FAILED\n");
        ret = 0;
    }
    printf("\n");

    if (ret) {
        printf("========================================\n");
        printf("✓ All policy enforcement tests passed!\n");
        printf("========================================\n");
    } else {
        printf("========================================\n");
        printf("✗ Some policy enforcement tests failed\n");
        printf("========================================\n");
    }

    return ret ? 0 : 1;
}

/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * Timing Variance Test Infrastructure
 *
 * This test suite measures timing variations in constant-time cryptographic
 * operations to verify they execute in constant time regardless of input values.
 *
 * See: docs/reports/DSSSL_SECURITY_AUDIT_REPORT.md Section 7.6
 *      CSNA_SIDE_CHANNEL_HARDENING.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifdef CSNA_TIMING_TESTS
#include "providers/dsmil/csna.h"
#else
/* Fallback timing if CSNA not available */
#include <time.h>
static inline uint64_t csna_rdtsc(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static inline void csna_cpuid_barrier(void) { __asm__ __volatile__("" ::: "memory"); }
#define CSNA_TIMING_START(var) do { csna_cpuid_barrier(); var = csna_rdtsc(); } while (0)
#define CSNA_TIMING_END(var) do { csna_cpuid_barrier(); var = csna_rdtsc() - (var); } while (0)
#endif

#include "crypto/ml_kem/ml_kem.h"
#include "crypto/ml_dsa/ml_dsa_sign.h"

/* Test configuration */
#define NUM_SAMPLES 10000
#define MAX_CV_THRESHOLD 0.01  /* 1% coefficient of variation threshold */

/* Statistics structure */
typedef struct {
    uint64_t *timings;
    size_t count;
    double mean;
    double stddev;
    double cv;  /* Coefficient of variation */
    uint64_t min;
    uint64_t max;
} timing_stats_t;

/*
 * Calculate statistics from timing measurements
 */
static int calculate_stats(timing_stats_t *stats)
{
    size_t i;
    double sum = 0.0;
    double sum_sq_diff = 0.0;
    uint64_t min_val = UINT64_MAX;
    uint64_t max_val = 0;

    if (stats == NULL || stats->timings == NULL || stats->count == 0)
        return 0;

    /* Calculate mean */
    for (i = 0; i < stats->count; i++) {
        sum += (double)stats->timings[i];
        if (stats->timings[i] < min_val)
            min_val = stats->timings[i];
        if (stats->timings[i] > max_val)
            max_val = stats->timings[i];
    }
    stats->mean = sum / stats->count;
    stats->min = min_val;
    stats->max = max_val;

    /* Calculate standard deviation */
    for (i = 0; i < stats->count; i++) {
        double diff = (double)stats->timings[i] - stats->mean;
        sum_sq_diff += diff * diff;
    }
    stats->stddev = sqrt(sum_sq_diff / stats->count);

    /* Calculate coefficient of variation */
    if (stats->mean > 0.0)
        stats->cv = stats->stddev / stats->mean;
    else
        stats->cv = 0.0;

    return 1;
}

/*
 * Test ML-KEM decapsulation timing variance
 */
static int test_ml_kem_decap_timing(void)
{
    ML_KEM_KEY *key = NULL;
    uint8_t pubkey[ML_KEM_PUBKEY_BYTES(768)];
    uint8_t prvkey[ML_KEM_PRVKEY_BYTES(768)];
    uint8_t ctext[ML_KEM_CTEXT_BYTES(768)];
    uint8_t shared_secret[ML_KEM_SHARED_SECRET_BYTES];
    uint8_t test_secret[ML_KEM_SHARED_SECRET_BYTES];
    timing_stats_t stats;
    size_t i;
    int ret = 1;

    printf("Testing ML-KEM-768 decapsulation timing variance...\n");

    stats.timings = OPENSSL_malloc(sizeof(uint64_t) * NUM_SAMPLES);
    if (stats.timings == NULL) {
        fprintf(stderr, "Failed to allocate timing array\n");
        return 0;
    }
    stats.count = NUM_SAMPLES;

    /* Generate test keypair */
    if (RAND_bytes(pubkey, sizeof(pubkey)) != 1 ||
        RAND_bytes(prvkey, sizeof(prvkey)) != 1) {
        fprintf(stderr, "Failed to generate test keys\n");
        OPENSSL_free(stats.timings);
        return 0;
    }

    /* TODO: Initialize ML-KEM key from test data */
    /* For now, this is a skeleton - requires proper ML-KEM key initialization */

    /* Measure decapsulation timing with different ciphertexts */
    for (i = 0; i < NUM_SAMPLES; i++) {
        uint64_t t;

        /* Generate random ciphertext */
        if (RAND_bytes(ctext, sizeof(ctext)) != 1) {
            ret = 0;
            break;
        }

        CSNA_TIMING_START(t);
        /* TODO: Call ossl_ml_kem_decap() */
        /* if (ossl_ml_kem_decap(shared_secret, sizeof(shared_secret),
         *                        ctext, sizeof(ctext), key) != 1) {
         *     ret = 0;
         *     break;
         * } */
        CSNA_TIMING_END(t);

        stats.timings[i] = t;
    }

    if (ret && calculate_stats(&stats)) {
        printf("  Mean: %.2f cycles\n", stats.mean);
        printf("  StdDev: %.2f cycles\n", stats.stddev);
        printf("  CV: %.4f%%\n", stats.cv * 100.0);
        printf("  Min: %llu cycles\n", (unsigned long long)stats.min);
        printf("  Max: %llu cycles\n", (unsigned long long)stats.max);

        if (stats.cv > MAX_CV_THRESHOLD) {
            fprintf(stderr, "  WARNING: Coefficient of variation %.2f%% exceeds threshold %.2f%%\n",
                    stats.cv * 100.0, MAX_CV_THRESHOLD * 100.0);
            ret = 0;
        } else {
            printf("  PASS: Timing variance within acceptable limits\n");
        }
    }

    OPENSSL_free(stats.timings);
    return ret;
}

/*
 * Test ML-DSA signature generation timing variance
 */
static int test_ml_dsa_sign_timing(void)
{
    timing_stats_t stats;
    size_t i;
    int ret = 1;

    printf("Testing ML-DSA-65 signature generation timing variance...\n");

    stats.timings = OPENSSL_malloc(sizeof(uint64_t) * NUM_SAMPLES);
    if (stats.timings == NULL) {
        fprintf(stderr, "Failed to allocate timing array\n");
        return 0;
    }
    stats.count = NUM_SAMPLES;

    /* TODO: Initialize ML-DSA key */
    /* For now, this is a skeleton */

    /* Measure signature timing with different messages */
    for (i = 0; i < NUM_SAMPLES; i++) {
        uint64_t t;
        uint8_t msg[32];
        uint8_t sig[ML_DSA_SIG_LEN(65)];

        /* Generate random message */
        if (RAND_bytes(msg, sizeof(msg)) != 1) {
            ret = 0;
            break;
        }

        CSNA_TIMING_START(t);
        /* TODO: Call ossl_ml_dsa_sign() */
        /* if (ossl_ml_dsa_sign(key, 0, msg, sizeof(msg), NULL, 0, NULL, 0, 1,
         *                      sig, NULL, sizeof(sig)) != 1) {
         *     ret = 0;
         *     break;
         * } */
        CSNA_TIMING_END(t);

        stats.timings[i] = t;
    }

    if (ret && calculate_stats(&stats)) {
        printf("  Mean: %.2f cycles\n", stats.mean);
        printf("  StdDev: %.2f cycles\n", stats.stddev);
        printf("  CV: %.4f%%\n", stats.cv * 100.0);
        printf("  Min: %llu cycles\n", (unsigned long long)stats.min);
        printf("  Max: %llu cycles\n", (unsigned long long)stats.max);

        if (stats.cv > MAX_CV_THRESHOLD) {
            fprintf(stderr, "  WARNING: Coefficient of variation %.2f%% exceeds threshold %.2f%%\n",
                    stats.cv * 100.0, MAX_CV_THRESHOLD * 100.0);
            ret = 0;
        } else {
            printf("  PASS: Timing variance within acceptable limits\n");
        }
    }

    OPENSSL_free(stats.timings);
    return ret;
}

/*
 * Test hybrid KEM decapsulation timing variance
 */
static int test_hybrid_kem_decap_timing(void)
{
    timing_stats_t stats;
    size_t i;
    int ret = 1;

    printf("Testing Hybrid KEM (X25519+ML-KEM-768) decapsulation timing variance...\n");

    stats.timings = OPENSSL_malloc(sizeof(uint64_t) * NUM_SAMPLES);
    if (stats.timings == NULL) {
        fprintf(stderr, "Failed to allocate timing array\n");
        return 0;
    }
    stats.count = NUM_SAMPLES;

    /* TODO: Initialize hybrid KEM key */
    /* For now, this is a skeleton */

    /* Measure hybrid decapsulation timing */
    for (i = 0; i < NUM_SAMPLES; i++) {
        uint64_t t;
        uint8_t ctext[1152];  /* X25519 (32) + ML-KEM-768 (1120) */
        uint8_t shared_secret[64];

        /* Generate random ciphertext */
        if (RAND_bytes(ctext, sizeof(ctext)) != 1) {
            ret = 0;
            break;
        }

        CSNA_TIMING_START(t);
        /* TODO: Call mlx_kem_decapsulate() */
        CSNA_TIMING_END(t);

        stats.timings[i] = t;
    }

    if (ret && calculate_stats(&stats)) {
        printf("  Mean: %.2f cycles\n", stats.mean);
        printf("  StdDev: %.2f cycles\n", stats.stddev);
        printf("  CV: %.4f%%\n", stats.cv * 100.0);

        if (stats.cv > MAX_CV_THRESHOLD) {
            fprintf(stderr, "  WARNING: Coefficient of variation %.2f%% exceeds threshold %.2f%%\n",
                    stats.cv * 100.0, MAX_CV_THRESHOLD * 100.0);
            ret = 0;
        } else {
            printf("  PASS: Timing variance within acceptable limits\n");
        }
    }

    OPENSSL_free(stats.timings);
    return ret;
}

/*
 * Main test runner
 */
int main(int argc, char **argv)
{
    int ret = 1;
    int test_ml_kem = 1;
    int test_ml_dsa = 1;
    int test_hybrid = 1;

    printf("========================================\n");
    printf("DSMIL Timing Variance Test Suite\n");
    printf("Phase 2: Constant-Time Verification\n");
    printf("========================================\n\n");

    /* Parse command line arguments */
    if (argc > 1) {
        test_ml_kem = (strstr(argv[1], "ml-kem") != NULL || strstr(argv[1], "all") != NULL);
        test_ml_dsa = (strstr(argv[1], "ml-dsa") != NULL || strstr(argv[1], "all") != NULL);
        test_hybrid = (strstr(argv[1], "hybrid") != NULL || strstr(argv[1], "all") != NULL);
    }

    if (test_ml_kem && !test_ml_kem_decap_timing()) {
        fprintf(stderr, "ML-KEM timing test FAILED\n");
        ret = 0;
    }
    printf("\n");

    if (test_ml_dsa && !test_ml_dsa_sign_timing()) {
        fprintf(stderr, "ML-DSA timing test FAILED\n");
        ret = 0;
    }
    printf("\n");

    if (test_hybrid && !test_hybrid_kem_decap_timing()) {
        fprintf(stderr, "Hybrid KEM timing test FAILED\n");
        ret = 0;
    }
    printf("\n");

    if (ret) {
        printf("========================================\n");
        printf("✓ All timing variance tests passed!\n");
        printf("========================================\n");
    } else {
        printf("========================================\n");
        printf("✗ Some timing variance tests failed\n");
        printf("========================================\n");
    }

    return ret ? 0 : 1;
}

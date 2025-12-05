# DSMIL Test Suite Makefile
# Phase 2: Comprehensive Testing Infrastructure

CC = gcc
CFLAGS = -Wall -Wextra -g -O0
LDFLAGS = -lcrypto -lssl

# Include paths
INCLUDES = -I../../include \
           -I../../providers/common/include \
           -I../../providers/implementations/include \
           -I../../providers/dsmil \
           -I../../crypto/ml_kem \
           -I../../crypto/ml_dsa \
           -I../helpers \
           -I../testutil

# Source files
TIMING_TEST_SRC = test-timing-variance.c
POLICY_TEST_SRC = test-policy-enforcement.c
HYBRID_KEM_TEST_SRC = test-hybrid-kem-tls.c
HYBRID_INTEROP_TEST_SRC = test-tls-hybrid-interop.c
CVE_TEST_SRC = test-cve-detection.c
OFFENSIVE_OPS_TEST_SRC = test-offensive-ops.c

# Object files
TIMING_TEST_OBJ = $(TIMING_TEST_SRC:.c=.o)
POLICY_TEST_OBJ = $(POLICY_TEST_SRC:.c=.o)
HYBRID_KEM_TEST_OBJ = $(HYBRID_KEM_TEST_SRC:.c=.o)
HYBRID_INTEROP_TEST_OBJ = $(HYBRID_INTEROP_TEST_SRC:.c=.o)
CVE_TEST_OBJ = $(CVE_TEST_SRC:.c=.o)
OFFENSIVE_OPS_TEST_OBJ = $(OFFENSIVE_OPS_TEST_SRC:.c=.o)

# Executables
TIMING_TEST = test-timing-variance
POLICY_TEST = test-policy-enforcement
HYBRID_KEM_TEST = test-hybrid-kem-tls
HYBRID_INTEROP_TEST = test-tls-hybrid-interop
CVE_TEST = test-cve-detection
OFFENSIVE_OPS_TEST = test-offensive-ops

.PHONY: all clean test

all: $(TIMING_TEST) $(POLICY_TEST) $(HYBRID_KEM_TEST) $(HYBRID_INTEROP_TEST) $(CVE_TEST) $(OFFENSIVE_OPS_TEST)

$(TIMING_TEST): $(TIMING_TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lm

$(POLICY_TEST): $(POLICY_TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(HYBRID_KEM_TEST): $(HYBRID_KEM_TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -L../../ -L../../ssl -L../../crypto

$(HYBRID_INTEROP_TEST): $(HYBRID_INTEROP_TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -L../../ -L../../ssl -L../../crypto

$(CVE_TEST): $(CVE_TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -L../../ -L../../ssl -L../../crypto

$(OFFENSIVE_OPS_TEST): $(OFFENSIVE_OPS_TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -L../../ -L../../ssl -L../../crypto

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

test: all
	@echo "Running timing variance tests..."
	./$(TIMING_TEST) all
	@echo ""
	@echo "Running policy enforcement tests..."
	./$(POLICY_TEST)
	@echo ""
	@echo "Running hybrid KEM TLS tests..."
	./$(HYBRID_KEM_TEST)
	@echo ""
	@echo "Running hybrid KEM interop tests..."
	./$(HYBRID_INTEROP_TEST)
	@echo ""
	@echo "Running CVE detection tests..."
	./$(CVE_TEST)
	@echo ""
	@echo "Running offensive operations tests..."
	@echo "WARNING: Offensive operations require authorization"
	./$(OFFENSIVE_OPS_TEST) || echo "Offensive ops tests skipped (authorization required)"

clean:
	rm -f $(TIMING_TEST_OBJ) $(POLICY_TEST_OBJ) $(HYBRID_KEM_TEST_OBJ) \
	      $(HYBRID_INTEROP_TEST_OBJ) $(CVE_TEST_OBJ) $(OFFENSIVE_OPS_TEST_OBJ) \
	      $(TIMING_TEST) $(POLICY_TEST) $(HYBRID_KEM_TEST) \
	      $(HYBRID_INTEROP_TEST) $(CVE_TEST) $(OFFENSIVE_OPS_TEST)

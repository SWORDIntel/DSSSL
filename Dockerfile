# DSSSL Container Image
# Multi-stage build for DSMIL-grade OpenSSL
#
# Copyright 2025 DSMIL Security Team. All Rights Reserved.

FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    perl \
    git \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install DSLLVM (hardened Clang/LLVM)
# NOTE: Replace with actual DSLLVM installation
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-17 main" > /etc/apt/sources.list.d/llvm.list && \
    apt-get update && apt-get install -y clang-17 llvm-17 && \
    ln -s /usr/bin/clang-17 /usr/bin/clang && \
    ln -s /usr/bin/clang++-17 /usr/bin/clang++

# Copy source
WORKDIR /build
COPY . /build/

# Build DSSSL
ARG BUILD_TYPE=world
RUN if [ "$BUILD_TYPE" = "world" ]; then \
        ./util/build-dsllvm-world.sh --clean; \
    else \
        ./util/build-dsllvm-dsmil.sh --clean; \
    fi

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy built OpenSSL
ARG BUILD_TYPE=world
COPY --from=builder /build/apps/openssl /opt/dsssl-${BUILD_TYPE}/bin/
COPY --from=builder /build/*.so* /opt/dsssl-${BUILD_TYPE}/lib64/
COPY --from=builder /build/configs/*.cnf /etc/dsssl/
COPY --from=builder /build/docs /opt/dsssl-${BUILD_TYPE}/share/doc/

# Create runtime directories
RUN mkdir -p /run/dsssl /var/log/dsssl && \
    chmod 755 /run/dsssl

# Environment
ENV PATH="/opt/dsssl-${BUILD_TYPE}/bin:$PATH" \
    LD_LIBRARY_PATH="/opt/dsssl-${BUILD_TYPE}/lib64:$LD_LIBRARY_PATH" \
    OPENSSL_CONF="/etc/dsssl/world.cnf" \
    DSMIL_PROFILE="WORLD_COMPAT" \
    DSMIL_EVENT_SOCKET="/run/dsssl/crypto-events.sock"

# Labels
LABEL org.opencontainers.image.title="DSSSL" \
      org.opencontainers.image.description="DSMIL-grade OpenSSL with Post-Quantum Cryptography" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="DSMIL Security Team" \
      org.opencontainers.image.licenses="Proprietary" \
      classification="UNCLASSIFIED // FOR OFFICIAL USE ONLY"

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /opt/dsssl-${BUILD_TYPE}/bin/openssl version || exit 1

WORKDIR /opt/dsssl-${BUILD_TYPE}

# Default command shows version
CMD ["/opt/dsssl-${BUILD_TYPE}/bin/openssl", "version", "-a"]

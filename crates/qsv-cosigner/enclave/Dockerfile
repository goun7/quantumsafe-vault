# Enclave image for the live Nitro e2e (docs/10 §4.53).
#
# Build context = repo root; scripts/nitro_build_enclave.sh drives
# `nitro-cli build-enclave-image` against this file (via a generated
# Dockerfile.gen when a non-default vault is requested).
#
# The vault allowlist travels as ENV: an enclave receives no run-time
# arguments, so QSV_VAULT is baked at build time and read by the binary
# (flags still override it for dev runs).
FROM rust:1-bookworm AS build
# aws-lc-sys (via rustls/aws-lc-rs) needs cmake on top of the toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p qsv-cosigner --features nsm --bin enclave_server

FROM debian:bookworm-slim
ENV QSV_VAULT=e2e-vault
COPY --from=build /build/target/release/enclave_server /enclave_server
# Fixed AF_VSOCK port — the e2e probe dials this.
ENTRYPOINT ["/enclave_server", "--port", "5005"]

# syntax=docker/dockerfile:1
#
# Build: static musl binaries in the official Rust Alpine image.
# Run:   FROM scratch with just the binaries, a CA bundle (ACME needs to verify the CA's
#        HTTPS endpoint) and a writable /data owned by an unprivileged user.

ARG RUST_VERSION=1.90

FROM rust:${RUST_VERSION}-alpine AS build
# C toolchain for ring and bundled SQLite; ca-certificates is copied into the final image.
RUN apk add --no-cache musl-dev ca-certificates
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin magicpipesd --bin magicpipes \
 && mkdir -p /out \
 && cp target/release/magicpipesd target/release/magicpipes /out/
# Fail the build if the binaries are not fully static (scratch has no libc).
RUN for b in /out/*; do \
      if ldd "$b" 2>&1 | grep -q '=>'; then echo "$b is dynamically linked" >&2; exit 1; fi; \
    done
RUN mkdir -p /rootfs/data /rootfs/tmp && chmod 1777 /rootfs/tmp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /rootfs/ /
COPY --from=build /out/magicpipesd /out/magicpipes /usr/local/bin/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    MAGICPIPESD_CONFIG=/etc/magicpipes/magicpipesd.toml
USER 65532:65532
VOLUME ["/data"]
EXPOSE 80 443 8443
ENTRYPOINT ["/usr/local/bin/magicpipesd"]

FROM rust:1.96-slim AS builder

WORKDIR /app

# rust:slim has no C toolchain; install what the C/C++ dependencies need
# (aws-lc-rs, libgit2-sys, openssl-sys via native-tls).
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

#COPY --chown=rust:rust . /app/
COPY . /app/

ARG CARGO_BUILD_EXTRA=" "
RUN cargo build --release ${CARGO_BUILD_EXTRA}

FROM debian:12-slim

COPY --from=builder /app/target/release/panamax /usr/local/bin

RUN apt update \
  && apt install -y \
    ca-certificates \
    git \
    libssl3 \
  && git config --global --add safe.directory '*'

ENTRYPOINT [ "/usr/local/bin/panamax" ]
CMD ["--help"]

FROM rust:1.99-bookworm AS build

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p attest-api

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/attest-api /usr/local/bin/attest-api

EXPOSE 8080
CMD ["attest-api"]

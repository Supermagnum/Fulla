# Fulla registry image for local/adversarial testing (plain HTTP, file-backed SQLite).
FROM docker.io/rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY templates ./templates
RUN cargo build --release --locked

FROM docker.io/debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/fulla /usr/local/bin/fulla
COPY --from=builder /build/migrations ./migrations
COPY --from=builder /build/templates ./templates
RUN mkdir -p /data
ENV DATABASE_URL=sqlite:/data/keyserver.db?mode=rwc
EXPOSE 8080
HEALTHCHECK --interval=3s --timeout=2s --retries=20 \
    CMD curl -sf http://127.0.0.1:8080/ || exit 1
CMD ["fulla"]

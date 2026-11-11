# Distanplay server — multi-stage build for Railway (or any container host).
FROM rust:1-bookworm AS build
WORKDIR /app
# Cache dependencies: build once with a stub main, then the real sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY migrations ./migrations
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 app
COPY --from=build /app/target/release/distanplay-server /usr/local/bin/distanplay-server
USER app
ENV RUST_LOG=info
EXPOSE 8080
CMD ["distanplay-server"]

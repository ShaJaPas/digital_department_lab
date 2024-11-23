FROM lukemathwalker/cargo-chef:latest as chef

WORKDIR /app

FROM chef AS planner

COPY Cargo.toml Cargo.lock diesel.toml ./
COPY src src
COPY migrations migrations
COPY acl acl

RUN cargo chef prepare

FROM chef AS builder
COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release
COPY . .
RUN cargo build --release
RUN mv ./target/release/digital_department ./app

FROM debian:stable-slim AS runtime

RUN apt-get update && apt-get install libpq5 -y

WORKDIR /app

COPY --from=builder /app/app /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/app"]

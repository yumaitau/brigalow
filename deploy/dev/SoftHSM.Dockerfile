FROM rust:1-bookworm AS build
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Take each test binary path from cargo's JSON output: its location under
# target/ depends on the cargo version's build-dir layout.
RUN cargo test --locked -p brigalow-crypto --test custody --features pkcs11-tests --no-run --message-format=json > /tmp/custody.json \
    && cp "$(grep -o '"executable":"[^"]*/custody-[^"]*"' /tmp/custody.json | cut -d'"' -f4)" /crypto-tests
RUN cargo test --locked -p brigalow-crypto --test private_ca --features pkcs11-tests --no-run --message-format=json > /tmp/private_ca.json \
    && cp "$(grep -o '"executable":"[^"]*/private_ca-[^"]*"' /tmp/private_ca.json | cut -d'"' -f4)" /ca-tests
RUN cargo test --locked -p brigalow-crypto --test recovery --features pkcs11-tests --no-run --message-format=json > /tmp/recovery.json \
    && cp "$(grep -o '"executable":"[^"]*/recovery-[^"]*"' /tmp/recovery.json | cut -d'"' -f4)" /recovery-tests
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /crypto-tests /crypto-tests
COPY --from=build /ca-tests /ca-tests
COPY --from=build /recovery-tests /recovery-tests
COPY deploy/dev/hsm_recover.py /hsm_recover.py
COPY deploy/dev/hsm_test.py /hsm_test.py
CMD ["python3", "/hsm_test.py"]

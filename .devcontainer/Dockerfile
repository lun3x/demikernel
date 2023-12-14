# Use a rust distribution as a base, so we have rustup installed
FROM rust:1.70.0

# Install specific toolchain and components needed (see rust-toolchain for details)
RUN rustup toolchain install nightly-2023-11-16-aarch64-unknown-linux-gnu
RUN rustup component add rustfmt --toolchain nightly-2023-11-16-aarch64-unknown-linux-gnu
RUN rustup component add clippy --toolchain nightly-2023-11-16-aarch64-unknown-linux-gnu
FROM rust:1.70.0

RUN rustup toolchain install nightly-2023-06-01

COPY .demienv/config.yaml /root

COPY ../ /code

WORKDIR /code

RUN make
FROM alpine:3.12.0

RUN apk add cmake make musl-dev bash

COPY config_for_scripts /
COPY install_compilers /
RUN ./install_compilers


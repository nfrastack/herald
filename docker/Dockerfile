# SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
#
# SPDX-License-Identifier: BSD-3-Clause

ARG DISTRO=alpine
ARG DISTRO_VARIANT=3.21

FROM docker.io/nfrastack/container-base:${DISTRO}_${DISTRO_VARIANT}

LABEL org.opencontainers.image.title         "Container DNS Companion"
LABEL org.opencontainers.image.description   "Dockerized web server with many customizable options"
LABEL org.opencontainers.image.url           "https://hub.docker.com/r/tiredofit/nginx"
LABEL org.opencontainers.image.documentation "https://github.com/nfrastack/container-dns-companion/blob/main/README.md"
LABEL org.opencontainers.image.source        "https://github.com/nfrastack/container-dns-companion.git"
LABEL org.opencontainers.image.authors       "Nfrastack <code@nfrastack.com>"
LABEL org.opencontainers.image.vendor        "Nfrastack <https://www.nfrastack.com>"
LABEL org.opencontainers.image.licenses      "BSD-3"

ARG CDC_VERSION
ARG GOLANG_VERSION

ENV CONTAINER_ENABLE_SCHEDULING=TRUE \
    CDC_VERSION=${CDC_VERSION:-"dev"} \
    CDC_USER=cdc \
    CDC_GROUP=cdc \
    IMAGE_VERSION=${CDC_VERSION} \
    IMAGE_NAME="nfrastack/container-dns-companion" \
    IMAGE_REPO_URL="https://github.com/nfrastack/cotnainer-dns-companion"

COPY / /usr/src/container-dns-companion

RUN echo "" && \
    CDC_BUILD_DEPS_ALPINE=" \
                                go \
                                make \
                          " \
                          && \
    \
    CDC_BUILD_DEPS_DEBIAN=" \
                                make \
                          " \
                          && \
    \
    echo "" && \
    source /container/base/functions/container/build && \
    \
    mkdir -p /usr/src/container/ && \
    cp \
        /usr/src/container-dns-companion/{CHANGELOG.md,LICENSE,README.md} \
                                                /usr/src/container/ \
                                                && \
    \
    container_build_log && \
    \
    create_user "${CDC_USER}" 1000 "${CDC_GROUP}" 1000 /dev/null && \
    package update && \
    package upgrade && \
    package install \
                    CDC_BUILD_DEPS \
                    && \
    \
    case "$(container_info distro)" in \
        "debian" ) \
            mkdir -p /usr/local/go ; \
            GOLANG_VERSION=${GOLANG_VERSION:-"$(curl -sSL https://golang.org/VERSION?m=text | head -n1 | sed "s|^go||g")"} ; \
            curl -sSLk  https://dl.google.com/go/go${GOLANG_VERSION}.linux-$(dpkg --print-architecture).tar.gz | tar xvfz - --strip 1 -C /usr/local/go ; \
            ln -sf /usr/local/go/bin/go /usr/local/bin/ ; \
            ln -sf /usr/local/go/bin/godoc /usr/local/bin/ ; \
            ln -sf /usr/local/go/bin/gfmt /usr/local/bin/ ;  \
        ;; \
    esac ; \
    \
    cd /usr/src/container-dns-companion && \
    \
    case "$(container_info arch)" in \
        aarch64) \
            GOARCH=amd64 ; \
        ;; \
        x86_64) \
            GOARCH=amd64 ; \
        ;; \
        * ) \
            echo >&2 "Error: unsupported architecture ($(container_info arch))" ; \
            exit 1 ; \
        ;; \
    esac ; \
    go \
        build \
            -ldflags " \
                        -s \
                        -w \
                        -X main.Version=${CDC_VERSION:-"$(head -n1 /usr/src/container-dns-companion/CHANGELOG.md | awk '{print $1}')"} \
                     " \
            -o /usr/local/bin/container-dns-companion \
            ./cmd/container-dns-companion \
            && \
    \
    cp -aR \
                /usr/src/container-dns-companion/docker/rootfs/*  \
            / && \
    \
    package remove \
                    CDC_BUILD_DEPS \
                    && \
    package cleanup && \
    rm -rf \
            /root/go \
            /tmp/* \
            /usr/local/bin/gfmt* \
            /usr/local/bin/go* \
            /usr/local/go


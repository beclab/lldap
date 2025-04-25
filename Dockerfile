FROM rust:1.85.1 as builder

RUN USER=root
WORKDIR /app
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./server ./server
COPY ./set-password ./set-password
COPY ./migration-tool ./migration-tool
COPY ./auth ./auth
RUN cargo build --release -p lldap

# Final image
FROM ubuntu:22.04

#ENV GOSU_VERSION 1.14
## Fetch gosu from git
#RUN set -eux; \
#        \
#        apk add --no-cache --virtual .gosu-deps \
#                ca-certificates \
#                dpkg \
#                gnupg \
#        ; \
#        \
#        dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
#        wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
#        wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
#        \
## verify the signature
#        export GNUPGHOME="$(mktemp -d)"; \
#        gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
#        gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
#        command -v gpgconf && gpgconf --kill all || :; \
#        rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
#        \
## clean up fetch dependencies
#        apk del --no-network .gosu-deps; \
#        \
#        chmod +x /usr/local/bin/gosu; \
## verify that the binary works
#        gosu --version; \
#        gosu nobody true

WORKDIR /app

#COPY --from=builder /app/app/index_local.html app/index.html
#COPY --from=builder /app/app/static app/static
#COPY --from=builder /app/app/pkg app/pkg
COPY --from=builder /app/target/release/lldap ./lldap
COPY docker-entrypoint.sh lldap_config.docker_template.toml ./
COPY scripts/bootstrap.sh ./

#RUN set -x \
#    && apk add --no-cache bash tzdata libgcc \
#    && chmod a+r -R ./

RUN chmod +x /app/lldap

ENV LDAP_PORT=3890
ENV HTTP_PORT=17170

EXPOSE ${LDAP_PORT} ${HTTP_PORT}

ENTRYPOINT ["/app/lldap","run"]
#ENTRYPOINT ["/app/docker-entrypoint.sh"]
#CMD ["run", "--config-file", "/data/lldap_config.toml"]
#HEALTHCHECK CMD ["/app/lldap", "healthcheck", "--config-file", "/data/lldap_config.toml"]
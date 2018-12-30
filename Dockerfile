FROM golang:1-alpine

ENV GOBIN=/bin
COPY . /go/src/github.com/fd/vault-plugin-secret-jwt
RUN cd /go/src/github.com/fd/vault-plugin-secret-jwt ; \
  go install -v .

FROM vault:1.0.1
COPY --from=0 /bin/vault-plugin-secret-jwt /plugins/vault-plugin-secret-jwt
COPY test/ /test/

ENTRYPOINT []
CMD ["/bin/sh", "/test/setup.sh"]

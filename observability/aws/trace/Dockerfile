FROM jaegertracing/jaeger:2.20.0 AS upstream

FROM alpine:3.21.3
RUN addgroup -S -g 10001 gluevenir \
    && adduser -S -D -H -u 10001 -G gluevenir gluevenir \
    && install -d -m 0755 /cmd/jaeger /etc/jaeger
COPY --from=upstream /cmd/jaeger/jaeger-linux /cmd/jaeger/jaeger-linux
COPY --chmod=0444 aws/trace/config.yaml /etc/jaeger/config.yaml
COPY --chmod=0555 aws/trace/start.sh /usr/local/bin/gluevenir-jaeger
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/gluevenir-jaeger"]

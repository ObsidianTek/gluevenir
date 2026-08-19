FROM otel/opentelemetry-collector-contrib:0.123.0 AS upstream

FROM alpine:3.21.3
RUN addgroup -S -g 10001 gluevenir \
    && adduser -S -D -H -u 10001 -G gluevenir gluevenir \
    && install -d -m 0755 /etc/otelcol-contrib
COPY --from=upstream /otelcol-contrib /otelcol-contrib
COPY --chmod=0444 aws/collector/config.yaml /etc/otelcol-contrib/config.yaml
USER 10001:10001
ENTRYPOINT ["/otelcol-contrib"]
CMD ["--config=/etc/otelcol-contrib/config.yaml"]

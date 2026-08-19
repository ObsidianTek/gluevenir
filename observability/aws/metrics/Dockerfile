FROM prom/prometheus:v3.2.1

COPY --chmod=0444 aws/metrics/prometheus.yml /etc/prometheus/prometheus.yml
COPY --chmod=0555 aws/metrics/start.sh /usr/local/bin/gluevenir-prometheus
ENTRYPOINT ["/usr/local/bin/gluevenir-prometheus"]

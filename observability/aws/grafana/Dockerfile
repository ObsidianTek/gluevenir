FROM python:3.12.11-alpine3.21 AS dashboard-builder
COPY shared/dashboards /input
COPY --chmod=0555 aws/grafana/generate_public_dashboards.py /generator.py
RUN python /generator.py --input-dir /input --output-dir /output

FROM grafana/grafana-oss:11.6.0

USER root
COPY --chmod=0444 aws/grafana/grafana.ini /etc/grafana/grafana.ini
COPY --chmod=0444 aws/grafana/provisioning/datasources/gluevenir.yaml /etc/grafana/provisioning/datasources/gluevenir.yaml
COPY --chmod=0444 aws/grafana/provisioning/dashboards/gluevenir.yaml /etc/grafana/provisioning/dashboards/gluevenir.yaml
COPY --from=dashboard-builder --chown=472:0 /output /var/lib/grafana/dashboards
COPY --chmod=0555 aws/grafana/start.sh /usr/local/bin/gluevenir-grafana
RUN find /var/lib/grafana/dashboards -type d -exec chmod 0555 {} + \
    && find /var/lib/grafana/dashboards -type f -exec chmod 0444 {} +
USER 472
ENV GF_PLUGINS_PREINSTALL_DISABLED=true
ENTRYPOINT ["/usr/local/bin/gluevenir-grafana"]

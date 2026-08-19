FROM nginxinc/nginx-unprivileged:1.27.4-alpine3.21

USER root
RUN rm -f /etc/nginx/conf.d/default.conf \
    && install -d -o 101 -g 0 -m 0750 /etc/nginx/conf.d \
    && install -d -o root -g root -m 0555 /etc/nginx/templates
COPY --chmod=0444 aws/viewer/default.conf.template /etc/nginx/templates/default.conf.template
USER 101

ENV NGINX_ENVSUBST_FILTER=^GLUEVENIR_OTLP_BEARER_TOKEN$
EXPOSE 8080

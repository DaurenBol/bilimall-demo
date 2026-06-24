#!/bin/sh
set -e
htpasswd -bnB "${SITE_USER:-bilimall}" "${SITE_PASS:-changeme}" > /etc/nginx/.htpasswd
exec nginx -g 'daemon off;'

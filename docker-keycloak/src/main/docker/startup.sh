#!/usr/bin/env bash

echo "Running startup script"

# shellcheck disable=SC2164
cd /opt/keycloak/bin

./kc.sh build

rm -f /opt/keycloak/data/*.jfr

exec ./kc.sh "$@"

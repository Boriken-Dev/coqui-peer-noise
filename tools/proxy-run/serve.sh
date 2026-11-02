#!/bin/bash
# The proxy's side of the run: a throwaway certificate, nginx ending TLS on 127.0.0.1, and the relay behind
# it, in a temporary directory that goes when stdin ends. Binds loopback only; touches nothing else.
# Arguments: nginx binary, node binary, HTTPS port, relay port, proxy read timeout for /idle/ in seconds.
set -u
nginx_bin=$1
node_bin=$2
port=$3
relay=$4
idle=$5
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /tmp/coqui-proxy-run.XXXXXX)
nginx_pid=""
relay_pid=""

cleanup() {
    [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null
    if [ -n "$nginx_pid" ]; then
        kill "$nginx_pid" 2>/dev/null
        wait "$nginx_pid" 2>/dev/null
    fi
    if [ -f "$work/access.log" ]; then
        while IFS= read -r line; do printf 'ACCESS %s\n' "$line"; done <"$work/access.log"
    fi
    grep -E 'emerg|alert|crit' "$work/error.log" 2>/dev/null | while IFS= read -r line; do
        printf 'NGINXERROR %s\n' "$line"
    done
    rm -rf "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$work/key.pem" -out "$work/cert.pem" -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 2>/dev/null || exit 2

sed -e "s|@WORK@|$work|g" -e "s|@PORT@|$port|g" -e "s|@RELAY@|$relay|g" -e "s|@IDLE@|$idle|g" \
    "$here/nginx.conf.template" >"$work/nginx.conf"
mkdir -p "$work/client" "$work/proxy" "$work/fastcgi" "$work/uwsgi" "$work/scgi"

# An unpacked package finds its libraries beside itself; a system nginx finds them where it always does.
export LD_LIBRARY_PATH="$(dirname "$nginx_bin")/../lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
version=$("$nginx_bin" -v 2>&1)
"$nginx_bin" -e "$work/error.log" -p "$work" -c "$work/nginx.conf" -t >/dev/null 2>"$work/test.log" || {
    cat "$work/test.log" >&2
    exit 3
}

# The relay reads scenarios from this script's stdin and writes its lines to this script's stdout.
"$node_bin" "$here/relay.mjs" "$relay" <&0 &
relay_pid=$!

"$nginx_bin" -e "$work/error.log" -p "$work" -c "$work/nginx.conf" >/dev/null 2>&1 &
nginx_pid=$!

spki=$(openssl x509 -in "$work/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER |
    openssl dgst -sha256 -binary | base64 -w0)
printf 'READY {"nginx":"%s","spki":"%s","cert":"%s","openssl":"%s"}\n' "$version" "$spki" \
    "$(base64 -w0 "$work/cert.pem")" "$(openssl version | cut -d' ' -f1,2)"

wait "$relay_pid"

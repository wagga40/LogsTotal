#!/bin/sh
set -e

# LOGSTOTAL_CADDY_DRYRUN=1 is a test-only seam, the docker-entrypoint.sh idiom: it renders
# the Caddyfile to stdout and exits instead of writing it and executing caddy. It sits
# AFTER every validation below, so the refusals stay on the tested path. Nothing in the
# container sets it.

# Validate inputs before interpolating into the Caddyfile. Caddy parses the
# resulting file as a shell-free config, but newlines / braces in env vars
# would still let an attacker inject directives (e.g. route hijack, log
# redirects). Reject anything that doesn't look like a hostname / bcrypt hash.

CADDYFILE=/etc/caddy/Caddyfile

# Where PROXY_TLS=custom certificates are mounted, and the prefix PROXY_TLS_CERT /
# PROXY_TLS_KEY are constrained to. Overridable only because a test cannot write to
# /etc/caddy on the machine running it. Not a boundary against a hostile .env — whoever
# can set PROXY_TLS_CERT can set this too — it stops a typo pointing the proxy at
# something outside the bind mount.
CADDY_CERT_DIR="${CADDY_CERT_DIR:-/etc/caddy/certs}"

# How TLS is terminated. `acme` is the default.
#   acme      Let's Encrypt against a public DOMAIN. Needs DNS and ports 80+443.
#   internal  Caddy's own CA. No DNS, no port 80, no internet — the air-gapped answer.
#             Clients trust it by installing the root Caddy writes to
#             /data/caddy/pki/authorities/local/root.crt inside the caddy_data volume.
#   custom    The operator's own certificate, from the ./certs bind mount.
#   off       Plain HTTP, for a network where something in front already terminates TLS.
#             The app must run COOKIE_INSECURE=true here or login silently fails.
proxy_tls="${PROXY_TLS:-acme}"
case "$proxy_tls" in
    acme | internal | custom | off) ;;
    *)
        echo "docker-caddy-entrypoint: invalid PROXY_TLS '$proxy_tls' — expected one of: acme, internal, custom, off." >&2
        exit 1
        ;;
esac

domain="${DOMAIN:-localhost}"
case "$domain" in
    *[!A-Za-z0-9.\-]*)
        echo "docker-caddy-entrypoint: invalid DOMAIN '$domain' — allowed chars: letters, digits, '.', '-'." >&2
        exit 1
        ;;
esac

email="${ACME_EMAIL:-}"
case "$email" in
    *[[:space:]]* | *\{* | *\}*)
        echo "docker-caddy-entrypoint: invalid ACME_EMAIL '$email' — whitespace or braces are not allowed." >&2
        exit 1
        ;;
esac

# Certificate paths matter only under PROXY_TLS=custom, and both are required there: half a
# pair renders a `tls` directive Caddy rejects at parse time, which is a crash loop rather
# than a message.
tls_cert="${PROXY_TLS_CERT:-}"
tls_key="${PROXY_TLS_KEY:-}"
if [ "$proxy_tls" = "custom" ]; then
    if [ -z "$tls_cert" ] || [ -z "$tls_key" ]; then
        echo "docker-caddy-entrypoint: PROXY_TLS=custom needs both PROXY_TLS_CERT and PROXY_TLS_KEY (paths under ${CADDY_CERT_DIR}, mounted from ./certs)." >&2
        exit 1
    fi
    for _path in "$tls_cert" "$tls_key"; do
        case "$_path" in
            "$CADDY_CERT_DIR"/*) ;;
            *)
                echo "docker-caddy-entrypoint: invalid certificate path '$_path' — must be under ${CADDY_CERT_DIR} (mounted from ./certs)." >&2
                exit 1
                ;;
        esac
        case "$_path" in
            *[[:space:]]* | *\{* | *\}* | *..*)
                echo "docker-caddy-entrypoint: invalid certificate path '$_path' — whitespace, braces and '..' are not allowed." >&2
                exit 1
                ;;
        esac
        if [ ! -f "$_path" ]; then
            echo "docker-caddy-entrypoint: certificate file '$_path' not found — put it in ./certs on the host." >&2
            exit 1
        fi
    done
fi

basic_auth_user="${BASIC_AUTH_USER:-}"
basic_auth_hash="${BASIC_AUTH_HASH:-}"
if [ -n "$basic_auth_user" ] || [ -n "$basic_auth_hash" ]; then
    if [ -z "$basic_auth_user" ] || [ -z "$basic_auth_hash" ]; then
        echo "docker-caddy-entrypoint: BASIC_AUTH_USER and BASIC_AUTH_HASH must be set together." >&2
        exit 1
    fi
    case "$basic_auth_user" in
        *[[:space:]]* | *\{* | *\}*)
            echo "docker-caddy-entrypoint: invalid BASIC_AUTH_USER — whitespace or braces are not allowed." >&2
            exit 1
            ;;
    esac
    case "$basic_auth_hash" in
        *[[:space:]]* | *\{* | *\}*)
            echo "docker-caddy-entrypoint: invalid BASIC_AUTH_HASH — whitespace or braces are not allowed." >&2
            exit 1
            ;;
    esac
fi

# One emitter, to stdout, rather than a copy per email/no-email and TLS-mode combination.
render_caddyfile() {
    # The site address carries the scheme decision: a bare hostname gets Caddy's Automatic
    # HTTPS, an explicit `http://` turns it off for that site. Nothing else disables it.
    site="$domain"
    [ "$proxy_tls" = "off" ] && site="http://${domain}"

    # An empty ACME_EMAIL must not render `email` with no argument, which Caddy rejects at
    # parse time — crash-looping the proxy on the documented manual HTTPS setup (set
    # COMPOSE_PROFILES=proxy by hand and bring the stack up). Caddy issues certificates
    # without an email; the only cost is that
    # the CA has no address for expiry warnings. Only `acme` talks to a CA, so only `acme`
    # emits the block at all.
    if [ "$proxy_tls" = "acme" ] && [ -n "$email" ]; then
        printf '{\n    email %s\n}\n\n' "$email"
    fi

    printf '%s {\n' "$site"

    case "$proxy_tls" in
        internal) printf '    tls internal\n' ;;
        custom) printf '    tls %s %s\n' "$tls_cert" "$tls_key" ;;
    esac

    if [ -n "$basic_auth_user" ] && [ -n "$basic_auth_hash" ]; then
        printf '    basicauth * {\n        %s %s\n    }\n' "$basic_auth_user" "$basic_auth_hash"
    fi

    printf '    reverse_proxy web:8000\n}\n'
}

if [ "$proxy_tls" = "acme" ] && [ -z "$email" ]; then
    echo "docker-caddy-entrypoint: ACME_EMAIL is not set — certificates will be issued without a contact address (no expiry notices from the CA)." >&2
fi

if [ "${LOGSTOTAL_CADDY_DRYRUN:-}" = "1" ]; then
    render_caddyfile
    exit 0
fi

render_caddyfile > "$CADDYFILE"

exec caddy run --config "$CADDYFILE" --adapter caddyfile

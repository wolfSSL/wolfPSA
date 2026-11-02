#!/bin/sh

# Run x509_crt_test.c and pk_test.c on Mbed TLS's test data, then the Mbed TLS
# migration guide client, client-tls-mbedtls.c, and Mbed TLS's sample
# programs, built unchanged from MBEDTLS_PATH, against the wolfSSL example
# server, one server per case. A program missing a feature macro prints
# "... not defined" and exits 0, so that output fails the case, and a case
# can require a line of output. A case whose wrapper, such as faketime, is
# not installed is skipped. Then Mbed TLS's server programs, against the
# wolfSSL example client and ssl_client1. WRAP prefixes the programs. Run by
# the Makefile in this directory, which sets the paths.

: "${BUILD_DIR:?}" "${WOLFSSL_PATH:?}" "${WOLFSSL_SERVER:?}" \
    "${WOLFSSL_CLIENT:?}" "${MBEDTLS_PATH:?}"

DATA=$MBEDTLS_PATH/framework/data_files
READY=$BUILD_DIR/server-ready
FAILS=0
SKIPS=0

if [ ! -f "$DATA/server5.crt" ]; then
    echo "$DATA not found, run git submodule update --init in $MBEDTLS_PATH"
    exit 1
fi

TESTS="x509_crt_test pk_test"
if [ "$MBEDTLS_THREADING_C" != 1 ]; then
    echo "SKIP: ssl_pthread_server: MBEDTLS_THREADING_C=1 not set"
    SKIPS=$((SKIPS + 1))
fi
for t in $TESTS; do
    (cd "$DATA" && $WRAP "$BUILD_DIR/$t") || FAILS=$((FAILS + 1))
done

# The example server and the programs run from the wolfSSL root, for its certs
start_server() {
    rm -f "$READY"
    (cd "$WOLFSSL_PATH" && exec "$WOLFSSL_SERVER" -R "$READY" $1) \
        >/dev/null 2>&1 &
    srv=$!
    i=0
    while [ ! -f "$READY" ] && [ $i -lt 50 ]; do
        i=$((i + 1))
        sleep 0.1
    done
}

# The migration guide client, on its port, with certs/server-cert.pem
C=client-tls-mbedtls
LO=127.0.0.1
TLS13="-p 11111 -d -v 4"
TLS12="-p 11111 -d -v 3"
GOT="tls_get() returned"
P=programs/ssl
# mini_client's built-in CA, test-ca2 from 2013, encodes its name as only the
# older server5 certs do, and wolfSSL compares encoded names
SERVER5="-p 4433 -d -c $DATA/server5-expired.crt -k $DATA/server5.key"
# Inside both validity periods: the CA ends 2023-09-22, the server 2014-03-08
CA2_DATE="faketime 2014-01-01"
# Signed by test-ca-sha256.crt, in certs.c's mbedtls_test_cas_pem
SERVER2="-p 4433 -d -c $DATA/server2-sha256.crt -k $DATA/server2.key"
# The wolfSSL example server's own certificate, from another CA
SERVER_WOLF="-p 4433 -d"
VERIFY="Verifying peer X.509 certificate..."
# A CA that wolfSSL refuses to load, then the server's CA
BUNDLE=$BUILD_DIR/ca-bundle.pem
cat "$WOLFSSL_PATH/certs/test/expired/expired-ca.pem" \
    "$WOLFSSL_PATH/certs/ca-cert.pem" > "$BUNDLE"

# name|program|arguments|server options|wrapper|expected exit code|
# expected output
while IFS='|' read -r name prog args sopts wrap expect want; do
    [ -z "$name" ] && continue
    if [ -n "$wrap" ] && ! command -v "${wrap%% *}" >/dev/null; then
        echo "SKIP: $name: ${wrap%% *} not found"
        SKIPS=$((SKIPS + 1))
        continue
    fi
    start_server "$sopts"
    out=$(cd "$WOLFSSL_PATH" && $wrap $WRAP "$BUILD_DIR/$prog" $args 2>&1)
    rc=$?
    if [ $rc -eq "$expect" ] && ! echo "$out" | grep -q "not defined" &&
            echo "$out" | grep -qF -- "$want"; then
        echo "PASS: $name"
    else
        echo "FAIL: $name: exit $rc: $out"
        FAILS=$((FAILS + 1))
    fi
    kill $srv 2>/dev/null
    wait $srv 2>/dev/null
done <<CASES
TLS 1.3|$C|$LO|$TLS13||0|$GOT 0
TLS 1.2|$C|$LO|$TLS12||0|$GOT 0
TLS 1.3 non-blocking|$C|-N $LO|$TLS13||0|$GOT 0
TLS 1.2 non-blocking|$C|-N $LO|$TLS12||0|$GOT 0
DER CA file|$C|-A certs/ca-cert.der $LO|$TLS13||0|$GOT 0
CA bundle, expired CA first|$C|-A $BUNDLE $LO|$TLS13||0|$GOT 0
wrong host, VERIFY_FAILED|$C|-S wrong.example.org $LO|$TLS13||1|$GOT -9984
wrong CA, VERIFY_FAILED|$C|-A certs/ca-ecc-cert.pem $LO|$TLS13||1|$GOT -9984
no CA file, X509_FILE_IO_ERROR|$C|-A certs/missing.pem $LO|$TLS13||1|$GOT -10496
not a certificate, X509_INVALID_FORMAT|$C|-A README.md $LO|$TLS13||1|$GOT -8576
IP address host, SSL_BAD_INPUT_DATA|$C|-S $LO $LO|$TLS13||1|$GOT -135
mini_client|$P/mini_client||$SERVER5|$CA2_DATE|0|
mini_client, expired CA, ssl_handshake_failed|$P/mini_client||$SERVER5||7|
ssl_client1|$P/ssl_client1||$SERVER2||0|$VERIFY ok
ssl_client1, untrusted, OPTIONAL|$P/ssl_client1||$SERVER_WOLF||0|$VERIFY failed
CASES
rm -f "$READY"

# The server programs listen on port 4433 until stopped. The exit code of a
# server is not checked.
start_program() {
    rm -f "$LOG"
    (cd "$WOLFSSL_PATH" && exec $WRAP "$BUILD_DIR/$1") >"$LOG" 2>&1 &
    srv=$!
    i=0
    while ! grep -q "Waiting for a remote connection" "$LOG" 2>/dev/null &&
            [ $i -lt 100 ]; do
        i=$((i + 1))
        sleep 0.1
    done
}

# Options for the wolfSSL example client, or a program
run_client() {
    case "$1" in
        -*) "$WOLFSSL_CLIENT" -p 4433 -g -A "$CAS" "$@" ;;
        *) $WRAP "$BUILD_DIR/$1" ;;
    esac
}

LOG=$BUILD_DIR/server.log
# The server's response contains mbedtls_ssl_get_ciphersuite()
RESPONSE="Successful connection using: TLS"
# The server programs send their certificate and the CAs of certs.c's
# mbedtls_test_cas_pem, and the wolfSSL client checks each of them
CAS=$BUILD_DIR/test-cas.pem
cat "$DATA/test-ca-sha256.crt" "$DATA/test-ca-sha1.crt" \
    "$DATA/test-ca2.crt" > "$CAS"
THREADED=
if [ "$MBEDTLS_THREADING_C" = 1 ]; then
    # ssl_pthread_server's limit, MAX_NUM_THREADS
    FIVE="-v 4&-v 3&-v 4&-v 3&$P/ssl_client1"
    THREADED="ssl_pthread_server, 5 clients at once|$P/ssl_pthread_server|$FIVE"
fi

# Prints the output of a client that does not get the expected result. A
# client after ! must fail.
check_client() {
    want=0
    c=$1
    case "$c" in
        !*) want=1; c=${c#!} ;;
    esac
    cout=$(cd "$WOLFSSL_PATH" && run_client $c 2>&1)
    rc=$?
    got=1
    if [ $rc -eq 0 ] && echo "$cout" | grep -qF -- "$RESPONSE"; then
        got=0
    fi
    if [ $got -ne $want ]; then
        printf '\nclient %s: exit %d: %s' "$c" $rc "$cout"
    fi
}

# name|program|clients, separated by ; and run one after another. Clients
# joined by & run at the same time.
while IFS='|' read -r name prog clients; do
    [ -z "$name" ] && continue
    start_program "$prog"
    out=
    IFS=';'
    for step in $clients; do
        IFS='&'
        pids=
        n=0
        for c in $step; do
            unset IFS
            check_client "$c" >"$LOG.$n" &
            pids="$pids $!"
            n=$((n + 1))
        done
        wait $pids
        for f in "$LOG".*; do
            out="$out$(cat "$f")"
        done
        rm -f "$LOG".*
    done
    unset IFS
    kill $srv 2>/dev/null
    wait $srv 2>/dev/null
    if [ -z "$out" ]; then
        echo "PASS: $name"
    else
        echo "FAIL: $name:$out
server: $(cat "$LOG")"
        FAILS=$((FAILS + 1))
    fi
done <<CASES
ssl_server, TLS 1.3, 1.2 and ssl_client1|$P/ssl_server|-v 4;-v 3;$P/ssl_client1
ssl_server, reset after a failure|$P/ssl_server|!-v 4 -A certs/ca-cert.pem;-v 4
ssl_fork_server, TLS 1.3 and 1.2|$P/ssl_fork_server|-v 4;-v 3
$THREADED
CASES
rm -f "$LOG"

if [ $FAILS -ne 0 ]; then
    echo "$FAILS failed"
    exit 1
fi
if [ $SKIPS -ne 0 ]; then
    echo "PASS: programs, $SKIPS skipped"
else
    echo "PASS: programs"
fi

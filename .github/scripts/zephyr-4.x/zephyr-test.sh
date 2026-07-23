#!/bin/bash
#
# zephyr-test.sh - Build and run the wolfPSA Zephyr samples/tests in a Docker
# container, across the supported Zephyr 4.x range. Mirrors the wolfSSL module's
# .github/scripts/zephyr-4.x/zephyr-test.sh (same GHCR images / west-init flow),
# but sets up BOTH modules a wolfPSA build needs -- the wolfSSL module (which
# supplies the wolfCrypt core, including the native Zephyr threading that a
# thread-safe wolfPSA build depends on) and wolfPSA itself -- and then runs the
# shared test runner (.github/scripts/run-tests.sh) rather than one sample.
#
# Usage:
#   ./zephyr-test.sh [options]
#
# Options:
#   -r, --repo <url>       wolfPSA git repo URL (the code under test)
#   -b, --branch <ref>     wolfPSA branch/revision (the code under test)
#   -z, --zephyr <version> Zephyr version tag (>= v4.3.0)
#   --wolfssl-repo <url>   wolfSSL repo URL   (default: wolfSSL/wolfssl)
#   --wolfssl-ref  <ref>   wolfSSL revision   (default: master)
#   -h, --help             Show this help
#
# Examples:
#   ./zephyr-test.sh -z v4.3.0
#   ./zephyr-test.sh -r https://github.com/me/wolfPSA -b my-fix -z v4.4.0

set -euo pipefail

# Defaults point at the upstream wolfSSL org. The workflow sets -r/-b to the
# wolfPSA code under test and leaves the wolfSSL repo/ref at these upstream
# defaults. The --wolfssl-repo/--wolfssl-ref flags remain for pointing at a
# fork locally.
WOLFPSA_REPO="https://github.com/wolfSSL/wolfPSA"
WOLFPSA_BRANCH="master"
ZEPHYR_VERSION="v4.4.0"
WOLFSSL_REPO="https://github.com/wolfSSL/wolfssl"
WOLFSSL_REF="master"

GHCR="ghcr.io/zephyrproject-rtos/zephyr-build"

usage() { sed -n '3,/^$/s/^# \?//p' "$0"; exit 0; }

# wolfPSA needs Zephyr >= 4.3 (the PSA_CRYPTO_PROVIDER_CUSTOM hook). Pick the SDK
# image the way the wolfSSL 4.x driver does.
select_docker_image() {
    local ver="${1#v}"
    local major="${ver%%.*}"
    local minor="${ver#*.}"
    minor="${minor%%.*}"
    if [[ "$major" -ge 4 && "$minor" -ge 4 ]]; then
        echo "${GHCR}:v0.29.2"   # Zephyr 4.4+ : SDK 1.x
    elif [[ "$major" -ge 4 && "$minor" -ge 3 ]]; then
        echo "${GHCR}:v0.28.8"   # Zephyr 4.3  : SDK 0.17.x
    else
        echo "ERROR: wolfPSA requires Zephyr >= 4.3 (got v${ver})" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--repo)        WOLFPSA_REPO="$2"; shift 2 ;;
        -b|--branch)      WOLFPSA_BRANCH="$2"; shift 2 ;;
        -z|--zephyr)      ZEPHYR_VERSION="$2"; shift 2 ;;
        --wolfssl-repo)   WOLFSSL_REPO="$2"; shift 2 ;;
        --wolfssl-ref)    WOLFSSL_REF="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

DOCKER_IMAGE=$(select_docker_image "$ZEPHYR_VERSION")
CONTAINER_NAME="wolfpsa-zephyr-${ZEPHYR_VERSION#v}-$$"

echo "==> wolfPSA repo/ref: ${WOLFPSA_REPO}@${WOLFPSA_BRANCH}"
echo "==> wolfSSL repo/ref: ${WOLFSSL_REPO}@${WOLFSSL_REF}"
echo "==> Zephyr version:   ${ZEPHYR_VERSION}"
echo "==> Docker image:     ${DOCKER_IMAGE}"

echo "==> Pulling Docker image..."
docker pull "${DOCKER_IMAGE}"

BUILD_SCRIPT=$(cat <<'INNER_SCRIPT'
#!/bin/bash
set -euo pipefail

ZEPHYR_VERSION="__ZEPHYR_VERSION__"
WOLFPSA_REPO="__WOLFPSA_REPO__"
WOLFPSA_BRANCH="__WOLFPSA_BRANCH__"
WOLFSSL_REPO="__WOLFSSL_REPO__"
WOLFSSL_REF="__WOLFSSL_REF__"

cd /workdir

echo "==> [container] west init (${ZEPHYR_VERSION})..."
west init --mr "${ZEPHYR_VERSION}" zephyrproject
cd zephyrproject/zephyr

# Inject the wolfSSL module (wolfCrypt core) and wolfPSA (self) into west.yml,
# the same sed approach the wolfSSL CI uses.
WSSL_BASE=$(echo "${WOLFSSL_REPO}" | sed 's|/[^/]*$||')
WPSA_BASE=$(echo "${WOLFPSA_REPO}" | sed 's|/[^/]*$||')
WSSL_REF=$(echo "${WOLFSSL_REF}"   | sed 's/\//\\\//g')
WPSA_REF=$(echo "${WOLFPSA_BRANCH}" | sed 's/\//\\\//g')

sed -i "s|remotes:|remotes:\n    - name: wolfssl\n      url-base: ${WSSL_BASE}\n    - name: wolfpsa\n      url-base: ${WPSA_BASE}|" west.yml
sed -i "s|projects:|projects:\n    - name: wolfssl\n      path: modules/crypto/wolfssl\n      remote: wolfssl\n      revision: ${WSSL_REF}\n    - name: wolfPSA\n      path: modules/crypto/wolfPSA\n      remote: wolfpsa\n      revision: ${WPSA_REF}|" west.yml
echo "==> [container] west.yml module entries:"; grep -A2 -E "wolfssl|wolfpsa|wolfPSA" west.yml
cd ..

echo "==> [container] west update..."
export GIT_TERMINAL_PROMPT=0
west update -n -o=--depth=1
west zephyr-export

echo "==> [container] Python deps..."
sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv >/dev/null 2>&1 || true
python3 -m venv .venv && source .venv/bin/activate
pip3 install west >/dev/null
pip3 install -r zephyr/scripts/requirements.txt >/dev/null

export ZEPHYR_BASE="/workdir/zephyrproject/zephyr"
if [[ -z "${ZEPHYR_SDK_INSTALL_DIR:-}" ]]; then
    SDK_DIR=$(find /opt -maxdepth 2 -name "zephyr-sdk-*" -type d 2>/dev/null | head -1)
    [[ -n "$SDK_DIR" ]] && export ZEPHYR_SDK_INSTALL_DIR="$SDK_DIR"
fi

# Both modules are in the manifest now, so the runner must NOT also add wolfPSA
# via EXTRA_ZEPHYR_MODULES.
echo "==> [container] Running the wolfPSA test suite..."
EXTRA_MODULE_ARG="" \
  bash modules/crypto/wolfPSA/.github/scripts/run-tests.sh
INNER_SCRIPT
)

BUILD_SCRIPT="${BUILD_SCRIPT//__ZEPHYR_VERSION__/$ZEPHYR_VERSION}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFPSA_REPO__/$WOLFPSA_REPO}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFPSA_BRANCH__/$WOLFPSA_BRANCH}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_REPO__/$WOLFSSL_REPO}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_REF__/$WOLFSSL_REF}"

cleanup() { docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true; }
trap cleanup EXIT
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

echo "==> Starting container..."
docker run --name "${CONTAINER_NAME}" --rm "${DOCKER_IMAGE}" bash -c "${BUILD_SCRIPT}"

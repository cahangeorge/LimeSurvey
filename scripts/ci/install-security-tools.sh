#!/bin/sh
set -eu

# Linux AMD64 hosted security job; archives are pinned by publisher asset SHA-256.
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'Security tool installer requires Linux AMD64.' >&2
    exit 1
fi
: "${1:?Pass the tool installation directory}"
tool_dir=$1
mkdir -p "$tool_dir"
download_dir=$(mktemp -d "${TMPDIR:-/tmp}/limesurvey-ci-tools.XXXXXX")
trap 'rm -rf -- "$download_dir"' EXIT
trap 'exit 1' HUP INT TERM

install_tool() {
    binary=$1
    url=$2
    checksum=$3
    archive=$download_dir/$binary.tar.gz
    curl --fail --silent --show-error --location --retry 2 \
        --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 \
        --output "$archive" "$url"
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status
    tar --extract --gzip --file "$archive" --directory "$tool_dir" \
        --no-same-owner --no-same-permissions "$binary"
    chmod 755 "$tool_dir/$binary"
}

install_tool gitleaks \
    https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
    551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
install_tool zizmor \
    https://github.com/zizmorcore/zizmor/releases/download/v1.30.1/zizmor-x86_64-unknown-linux-gnu.tar.gz \
    e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a
install_tool actionlint \
    https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
    8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
install_tool trivy \
    https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz \
    c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f

#!/usr/bin/env bash

set -euo pipefail

module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
nginx_source="$module_root/.ci/nginx"
test_output="$module_root/.ci/test-output"
build_jobs="${TEST_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
mkdir -p "$test_output"
exec > >(tee "$test_output/run.log") 2>&1

configure_args=(
    --prefix="$nginx_source/test-prefix"
    --with-debug
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_realip_module
    --with-http_sub_module
    --with-http_json_module
    --with-stream
    --with-stream_ssl_module
    --with-stream_realip_module
)

if [[ "${TEST_EXPR:-enabled}" == enabled ]]; then
    configure_args+=(--add-module="$module_root/.ci/ngx_expr_module")
    export TEST_NGINX_EXPR=1
fi

if [[ "${TEST_MODULE_LINK:-static}" == dynamic ]]; then
    configure_args+=(--with-compat --add-dynamic-module="$module_root")
else
    configure_args+=(--add-module="$module_root")
fi

if [[ "${TEST_SANITIZE:-disabled}" == enabled ]]; then
    configure_args+=(
        --with-cc-opt="-O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
        --with-ld-opt="-fsanitize=address,undefined"
    )
    export ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1:abort_on_error=1
    export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
fi

cd "$nginx_source"
sh ./configure "${configure_args[@]}"
make -j"$build_jobs"

export TEST_NGINX_BINARY="$nginx_source/objs/nginx"
export PERL5LIB="$module_root/.ci/nginx-tests/lib"
export TMPDIR="$(mktemp -d /tmp/nginx-module-test.XXXXXX)"
export TEST_NGINX_LEAVE=1
export TEST_NGINX_SERVROOT="$TMPDIR/servroot"
collect_logs() {
    find "$TMPDIR" -type f -name '*.log' -exec cp --parents {} "$test_output/" \;
}
trap collect_logs EXIT
if [[ "$(id -u)" == 0 ]]; then
    export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-user root;}"
fi
if [[ "${TEST_MODULE_LINK:-static}" == dynamic ]]; then
    export TEST_NGINX_GLOBALS="${TEST_NGINX_GLOBALS:-} load_module $nginx_source/objs/ngx_http_secure_link_hmac_module.so;"
fi
"$TEST_NGINX_BINARY" -V

cd "$module_root"
shopt -s nullglob
tests=()
for test_file in t/*.t; do
    tests+=("$test_file")
done
if (( ${#tests[@]} == 0 )); then
    echo "No tests selected" >&2
    exit 1
fi
prove -v "${tests[@]}"

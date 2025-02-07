#!/usr/bin/env bash
set -euo pipefail

NIXDL=$1
test_download_deps() {
    expected_output=$(cat <<EOF
/nix/store/f4dfwhawi5kn71k0q1rj296w33i61vp6-libunistring-1.2
/nix/store/kx9pbw29jml0fgrpkb89f029w25qyxwc-xgcc-13.3.0-libgcc
/nix/store/h44h6473all3qkrjjhkm3v0fv63lqyms-libidn2-2.3.7
/nix/store/5adwdl39g3k9a2j0qadvirnliv4r7pwd-glibc-2.39-52
/nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1
Hello, world!
EOF
)

    actual_output=$("$NIXDL" /nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1 && /nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1/bin/hello)

    if [[ "$expected_output" = "$actual_output" ]]; then
        echo "Test passed: Output matches expected result"
    else
        echo "Test failed: Output does not match expected result"
        echo "Expected:"
        echo "$expected_output"
        echo "Actual:"
        echo "$actual_output"
        exit 1
    fi
}
echo test_download_deps && test_download_deps

test_download_skip_deps() {
    expected_output=$(cat <<EOF
/nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1
EOF
)

    actual_output=$("$NIXDL" -skip-dependencies /nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1 && test -x /nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1/bin/hello)

    if [[ "$expected_output" = "$actual_output" ]]; then
        echo "Test passed: Output matches expected result"
    else
        echo "Test failed: Output does not match expected result"
        echo "Expected:"
        echo "$expected_output"
        echo "Actual:"
        echo "$actual_output"
        exit 1
    fi
}

rm -rf /nix/store
mkdir /nix/store
echo test_download_skip_deps && test_download_skip_deps

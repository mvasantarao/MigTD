#!/bin/bash

set -euo pipefail

##==============================================================================
##
## Script to fix libservtd_attest.a for application linking
## Author: Mike Brasher <mikbras@microsoft.com>
##
##==============================================================================

##==============================================================================
##
## Find libservtd_attest.a (there may be more than one)
##
##==============================================================================

targets="../../deps/linux-sgx/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux/libservtd_attest.a"

##==============================================================================
##
## Find tlibc library
##
##==============================================================================

tlibc_lib=$(find ../../deps/linux-sgx -name libtlibc.a)
if [ ! -f "${tlibc_lib}" ]; then
    echo "$0: tlibc lib not found"
    exit 1;
fi

##==============================================================================
##
## Find sgxssl library
##
##==============================================================================

sgxssl_lib=$(find ../../deps/linux-sgx -name libsgx_tsgxssl_crypto.a)
if [ ! -f "${sgxssl_lib}" ]; then
    echo "$0: sgxssl lib not found"
    exit 1;
fi

tmpdir=$(mktemp -d)
trap 'rm -f -- "$tmpdir/servtd_qve_utils.o" "$tmpdir/libservtd_attest_extras.c" "$tmpdir/libservtd_attest_extras.o"; rmdir -- "$tmpdir"' EXIT

##==============================================================================
##
## Remove unwanted objects from servtd_attest archive. This deletes all objects
## found in libsgx_tsgxssl_crypto.a from libservtd_attest.a. It also deletes
## most objects found in libtlibc.a from libservtd_attest.a (a few objects are
## spared, since tlibc introduces non-standard symbols, such as spinlocks,
## heap initialization, and various non-standard string functions).
##
##==============================================================================

for i in ${targets}
do
    lib="${i%.a}_app.a"
    cp "${i}" "${lib}"
    if [ "$?" != "0" ]; then
        echo "$0: failed to copy ${i} to ${lib}"
        exit 1;
    fi
    ar d ${lib} $(ar t ${tlibc_lib} | grep -v spinlock.o | grep -v sbrk.o | grep -v memset | grep -v memcpy )
    ar d ${lib} $(ar t ${sgxssl_lib})

    # Keep fallback exit-registration shims, but let host libc's strong symbols
    # override them where libc provides those functions.
    archive_path=$(realpath "${lib}")
    if ! (
        cd "${tmpdir}" &&
        ar x "${archive_path}" servtd_qve_utils.o &&
        objcopy --weaken-symbol=atexit --weaken-symbol=__cxa_atexit servtd_qve_utils.o &&
        ar r "${archive_path}" servtd_qve_utils.o &&
        ranlib "${archive_path}"
    ); then
        echo "$0: failed to localize atexit symbols in ${lib}"
        exit 1
    fi
    echo "Created ${lib}"
done

##==============================================================================
##
## Add object with extra code to archive. The errno-related object was removed
## above, so its definition is added here to compensate.
##
##==============================================================================

src=${tmpdir}/libservtd_attest_extras.c
obj=${tmpdir}/libservtd_attest_extras.o

cat > ${src} <<END
int* __errno()
{
    extern int* __errno_location();
    return __errno_location();
}
END

gcc -c ${src} -o ${obj}
if [ "$?" != "0" ]; then
    echo "$0: compile failed: ${src}"
    exit 1;
fi

for i in ${targets}
do
    lib="${i%.a}_app.a"
    ar r "${lib}" "${obj}"
done
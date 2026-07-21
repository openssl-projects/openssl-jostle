#
#  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
#
#  Licensed under the Apache License 2.0 (the "License"). You may not use
#  this file except in compliance with the License.  You can obtain a copy
#  in the file LICENSE in the source distribution or at
#  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
#

cmake_minimum_required(VERSION 3.30)
project(interface C)

set(CMAKE_C_STANDARD 11)

MESSAGE(${CMAKE_SYSTEM_NAME})

if (NOT DEFINED ENV{LS_CPU_ARCH})
    set(BC_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
    message("using CMAKE_SYSTEM_PROCESSOR ${BC_ARCH}")
else ()
    set(BC_ARCH $ENV{LS_CPU_ARCH})
    message("using LS_CPU_ARCH ${BC_ARCH}")
endif ()

# Normalize architecture naming for Windows resource folder layout.
set(BC_ARCH_RESOURCE "${BC_ARCH}")
string(TOLOWER "${BC_ARCH_RESOURCE}" BC_ARCH_RESOURCE)
if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    if (BC_ARCH_RESOURCE STREQUAL "x86_64")
        # Keep as-is
    elseif (BC_ARCH_RESOURCE STREQUAL "amd64" OR BC_ARCH_RESOURCE STREQUAL "x64" OR BC_ARCH_RESOURCE STREQUAL "x86-64")
        set(BC_ARCH_RESOURCE "x86_64")
    endif ()
endif ()
message("BC_ARCH_RESOURCE = ${BC_ARCH_RESOURCE}")

if (NOT DEFINED ENV{JAVA_HOME})
    MESSAGE(FATAL_ERROR "ENV VAR JAVA_HOME is not defined")
else ()
    SET(JAVA_HOME $ENV{JAVA_HOME})
    MESSAGE("JAVA_HOME = ${JAVA_HOME}")
endif ()


if (NOT DEFINED ENV{OPENSSL_PREFIX})
    MESSAGE(FATAL_ERROR "ENV VAR OPENSSL_PREFIX is not defined")
else ()
    file(TO_CMAKE_PATH "$ENV{OPENSSL_PREFIX}" OPENSSL_PREFIX)
    message("OpenSSL Prefix: ${OPENSSL_PREFIX}")
endif ()


get_filename_component(JAVA_PRJ_HOME "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)


#
# FIPS interface libraries - shared source lists, used by every OS branch.
#
# The FIPS variant compiles the SAME util/ layer into a SEPARATE shared
# library: its own copy of the process globals holds a FIPS-only
# OSSL_LIB_CTX (loaded via jostle_ctx_init_fips), so a FIPS and a non-FIPS
# Jostle provider can coexist in one JVM.
#
# JNI glue is FIPS-specific only: JNI binds native methods by
# class-name-derived symbol, so the FIPS library exports Java_*_fips_*
# symbols for the org.openssl.jostle.jcajce.provider.fips.* classes and
# deliberately does NOT compile the base jni/ glue (identical Java_* symbols
# in two loaded libraries would resolve by load order).
#
# FFI glue is shared as-is: FFI callers resolve the FIPS library's exports
# with a library-scoped lookup (SymbolLookup.libraryLookup on the extracted
# FIPS lib), so identical export names across the two libraries are
# unambiguous. JoFips_set_openssl_module is the FIPS-specific init entry.
#
# The FIPS targets carry no operations-test fault injection and no coverage
# instrumentation in a SHIPPED build - neither must ship inside the FIPS
# interface library. As with the base targets, both are strictly env-gated (a
# test/measurement build): JOSTLE_OPS is added ONLY when JOSTLE_OPS_TEST is set
# (jni/ops.c and jni/ops_fips_jni.c compile to nothing without it, so the
# shipped library exports no operations-test symbols), and the llvm coverage
# flags are added ONLY when JOSTLE_COVERAGE is set (osx, mirroring the base
# targets). With neither env var set the FIPS library is clean.
#
set(FIPS_UTIL_SOURCES
        fips/util/jo_assert.h
        fips/util/encapdecap.h
        fips/util/encapdecap.c
        fips/util/block_cipher_ctx.h
        fips/util/block_cipher_ctx.c
        fips/util/ccm_ctx.h
        fips/util/ccm_ctx.c
        fips/util/ctr_u128_t.h
        fips/util/ctr_u128_t.c
        fips/util/bc_err_codes.h
        fips/util/key_spec.c
        fips/util/key_spec.h
        fips/util/asn1_util.c
        fips/util/asn1_util.h
        fips/util/ops.h
        fips/util/ops.c
        fips/util/kdf.h
        fips/util/kdf.c
        fips/util/mac.h
        fips/util/mac.c
        fips/util/md.c
        fips/util/md.h
        fips/util/rand.c
        fips/util/rand.h
        fips/util/rand/rand_upcall.h
        fips/util/rand/jostle_lib_ctx.h
        fips/util/rand/jostle_lib_ctx.c
        fips/util/rand/jostle_fips_ctx.h
        fips/util/rand/jostle_fips_ctx.c
        fips/util/rsa.h
        fips/util/rsa.c
        fips/util/rsa_oaep.h
        fips/util/rsa_oaep.c
        fips/util/rsa_pkcs1.h
        fips/util/rsa_pkcs1.c
        fips/util/ec.h
        fips/util/ec.c
        fips/util/dsa.h
        fips/util/dsa.c
        fips/util/dh.h
        fips/util/dh.c
        fips/util/xec.h
        fips/util/xec.c
)

set(FIPS_JNI_GLUE_SOURCES
        fips/jni/openssl_fips_jni.c
        fips/jni/ops_fips_jni.c
        fips/jni/md_fips_jni.c
        fips/jni/block_cipher_fips_jni.c
        fips/jni/ccm_fips_jni.c
        fips/jni/mac_fips_jni.c
        fips/jni/rand_fips_jni.c
        fips/jni/spec_fips_jni.c
        fips/jni/asn1_fips_jni.c
        fips/jni/rsa_fips_jni.c
        fips/jni/rsa_oaep_fips_jni.c
        fips/jni/rsa_pkcs1_fips_jni.c
        fips/jni/ec_fips_jni.c
        fips/jni/dsa_fips_jni.c
        fips/jni/dh_fips_jni.c
        fips/jni/xec_fips_jni.c
        fips/jni/kdf_fips_jni.c
        fips/jni/rand_upcall_jni.h
        fips/jni/rand_upcall_jni.c
        fips/jni/byte_array_critical.c
        fips/jni/byte_array_critical.h
        fips/jni/bytearrays.c
        fips/jni/bytearrays.h
)

set(FIPS_FFI_GLUE_SOURCES
        fips/ffi/md_ffi.c
        fips/ffi/rand_ffi.c
        fips/ffi/mac_ffi.c
        fips/ffi/ffi.h
        fips/ffi/ffi.c
        fips/ffi/types.h
        fips/ffi/native_info_ffi.h
        fips/ffi/native_info_ffi.c
        fips/ffi/openssl_ffi.h
        fips/ffi/openssl_ffi.c
        fips/ffi/openssl_fips_ffi.h
        fips/ffi/openssl_fips_ffi.c
        fips/ffi/block_cipher_ni_ffi.c
        fips/ffi/ccm_ni_ffi.c
        fips/ffi/spec_ni_ffi.c
        fips/ffi/asn1_ni_ffi.c
        fips/ffi/kdf_ffi.c
        fips/ffi/rand_upcall_ffi.h
        fips/ffi/rand_upcall_ffi.c
        fips/ffi/rsa_ni_ffi.c
        fips/ffi/rsa_oaep_ni_ffi.c
        fips/ffi/rsa_pkcs1_ni_ffi.c
        fips/ffi/ec_ni_ffi.c
        fips/ffi/dsa_ni_ffi.c
        fips/ffi/dh_ni_ffi.c
        fips/ffi/xec_ni_ffi.c
)


if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" AND (${BC_ARCH} STREQUAL "arm64" OR ${BC_ARCH} STREQUAL "x86_64"))


    #
    # OSX
    #


    SET(OPTIONS "-O3")
    SET(OPEN_SSL_LIB "/lib/libcrypto.3.dylib")
    if (${BC_ARCH} STREQUAL "arm64")
        SET(INSTALL_PATH "${JAVA_PRJ_HOME}/jostle/src/main/resources/native/osx/arm64/")
    else ()
        SET(INSTALL_PATH "${JAVA_PRJ_HOME}/jostle/src/main/resources/native/osx/x86_64/")
    endif ()
    SET(JNI_INCLUDE "${JAVA_HOME}/include/" "${JAVA_HOME}/include/darwin" "${JAVA_PRJ_HOME}/jostle/build/generated/sources/headers/java/main")

    #
    # --- JNI Library
    #
    add_library(interface_jni SHARED
            nonfips/jni/md_jni.c
            nonfips/jni/rand_jni.c
            nonfips/jni/mac_jni.c
            nonfips/jni/native_info_jni.c
            nonfips/jni/open_ssl_jni.c
            nonfips/jni/block_cipher_ni_jni.c
            nonfips/jni/ccm_ni_jni.c
            nonfips/jni/spec_ni_jni.c
            nonfips/jni/mldsa_ni_jni.c
            nonfips/jni/slhdsa_ni_jni.c
            nonfips/jni/mlkem_ni_jni.c
            nonfips/jni/asn1_ni_jni.c
            nonfips/jni/ks_jni.c
            nonfips/util/jo_assert.h
            nonfips/util/mldsa.h
            nonfips/util/mldsa.c
            nonfips/util/slhdsa.h
            nonfips/util/slhdsa.c
            nonfips/util/mlkem.h
            nonfips/util/mlkem.c
            nonfips/util/encapdecap.h
            nonfips/util/encapdecap.c
            nonfips/util/block_cipher_ctx.h
            nonfips/util/block_cipher_ctx.c
            nonfips/util/ccm_ctx.h
            nonfips/util/ccm_ctx.c
            nonfips/util/ctr_u128_t.h
            nonfips/util/ctr_u128_t.c
            nonfips/util/bc_err_codes.h
            nonfips/util/key_spec.c
            nonfips/util/key_spec.h
            nonfips/jni/byte_array_critical.c
            nonfips/jni/byte_array_critical.h
            nonfips/jni/bytearrays.c
            nonfips/jni/bytearrays.h
            nonfips/util/asn1_util.c
            nonfips/util/asn1_util.h
            nonfips/util/ks.h
            nonfips/util/ks.c
            nonfips/util/ops.h
            nonfips/util/ops.c
            nonfips/jni/ops.c
            nonfips/jni/kdf_jni.c
            nonfips/util/kdf.h
            nonfips/util/kdf.c
            nonfips/util/mac.h
            nonfips/util/mac.c
            nonfips/util/md.c
            nonfips/util/md.h
            nonfips/util/rand.c
            nonfips/util/rand.h
            nonfips/util/rand/rand_upcall.h
            nonfips/util/rand/jostle_lib_ctx.h
            nonfips/util/rand/jostle_lib_ctx.c
            nonfips/jni/rand_upcall_jni.h
            nonfips/jni/rand_upcall_jni.c
            nonfips/jni/ed_jni.c
            nonfips/jni/rsa_ni_jni.c
            nonfips/jni/rsa_oaep_ni_jni.c
            nonfips/jni/rsa_pkcs1_ni_jni.c
            nonfips/jni/ec_ni_jni.c
            nonfips/jni/dsa_ni_jni.c
            nonfips/jni/dh_ni_jni.c
            nonfips/jni/xec_ni_jni.c
            nonfips/util/edec.h
            nonfips/util/edec.c
            nonfips/util/rsa.h
            nonfips/util/rsa.c
            nonfips/util/rsa_oaep.h
            nonfips/util/rsa_oaep.c
            nonfips/util/rsa_pkcs1.h
            nonfips/util/rsa_pkcs1.c
            nonfips/util/ec.h
            nonfips/util/ec.c
            nonfips/util/dsa.h
            nonfips/util/dsa.c
            nonfips/util/dh.h
            nonfips/util/dh.c
            nonfips/util/xec.h
            nonfips/util/xec.c
    )

    target_include_directories(interface_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_jni PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_jni PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        message("OPS Test Enabled")
        target_compile_definitions(interface_jni PUBLIC JOSTLE_OPS)
    endif ()
    if (DEFINED ENV{JOSTLE_COVERAGE})
        message("Coverage instrumentation enabled (JNI)")
        target_compile_options(interface_jni PRIVATE -fprofile-instr-generate -fcoverage-mapping -g)
        target_link_options(interface_jni PRIVATE -fprofile-instr-generate)
    endif ()

    # ---


    #
    # -- FFI Library
    #
    add_library(interface_ffi SHARED
            nonfips/ffi/md_ffi.c
            nonfips/ffi/rand_ffi.c
            nonfips/ffi/mac_ffi.c
            nonfips/ffi/ffi.h
            nonfips/ffi/ffi.c
            nonfips/ffi/types.h
            nonfips/ffi/native_info_ffi.h
            nonfips/ffi/native_info_ffi.c
            nonfips/ffi/openssl_ffi.h
            nonfips/ffi/openssl_ffi.c
            nonfips/ffi/block_cipher_ni_ffi.c
            nonfips/ffi/ccm_ni_ffi.c
            nonfips/ffi/spec_ni_ffi.c
            nonfips/ffi/mldsa_ni_ffi.c
            nonfips/ffi/mlkem_ni_ffi.c
            nonfips/ffi/slh_dsa_ni_ffi.c
            nonfips/ffi/asn1_ni_ffi.c
            nonfips/ffi/ks_ffi.c
            nonfips/util/jo_assert.h
            nonfips/util/mldsa.h
            nonfips/util/mldsa.c
            nonfips/util/slhdsa.h
            nonfips/util/slhdsa.c
            nonfips/util/mlkem.h
            nonfips/util/mlkem.c
            nonfips/util/encapdecap.h
            nonfips/util/encapdecap.c
            nonfips/util/block_cipher_ctx.h
            nonfips/util/block_cipher_ctx.c
            nonfips/util/ccm_ctx.h
            nonfips/util/ccm_ctx.c
            nonfips/util/ctr_u128_t.h
            nonfips/util/ctr_u128_t.c
            nonfips/util/bc_err_codes.h
            nonfips/util/key_spec.c
            nonfips/util/key_spec.h
            nonfips/util/asn1_util.c
            nonfips/util/asn1_util.h
            nonfips/util/ks.h
            nonfips/util/ks.c
            nonfips/util/ops.h
            nonfips/util/ops.c
            nonfips/ffi/kdf_ffi.c
            nonfips/util/kdf.h
            nonfips/util/kdf.c
            nonfips/util/mac.h
            nonfips/util/mac.c
            nonfips/util/md.c
            nonfips/util/md.h
            nonfips/util/rand.c
            nonfips/util/rand.h
            nonfips/util/rand/rand_upcall.h
            nonfips/util/rand/jostle_lib_ctx.h
            nonfips/util/rand/jostle_lib_ctx.c
            nonfips/ffi/rand_upcall_ffi.h
            nonfips/ffi/rand_upcall_ffi.c
            nonfips/ffi/ed_ni_ffi.c
            nonfips/ffi/rsa_ni_ffi.c
            nonfips/ffi/rsa_oaep_ni_ffi.c
            nonfips/ffi/rsa_pkcs1_ni_ffi.c
            nonfips/ffi/ec_ni_ffi.c
            nonfips/ffi/dsa_ni_ffi.c
            nonfips/ffi/dh_ni_ffi.c
            nonfips/ffi/xec_ni_ffi.c
            nonfips/util/edec.h
            nonfips/util/edec.c
            nonfips/util/rsa.h
            nonfips/util/rsa.c
            nonfips/util/rsa_oaep.h
            nonfips/util/rsa_oaep.c
            nonfips/util/rsa_pkcs1.h
            nonfips/util/rsa_pkcs1.c
            nonfips/util/ec.h
            nonfips/util/ec.c
            nonfips/util/dsa.h
            nonfips/util/dsa.c
            nonfips/util/dh.h
            nonfips/util/dh.c
            nonfips/util/xec.h
            nonfips/util/xec.c
    )
    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        message("OPS Test Enabled")
        target_compile_definitions(interface_ffi PUBLIC JOSTLE_OPS)
    endif ()
    if (DEFINED ENV{JOSTLE_COVERAGE})
        message("Coverage instrumentation enabled (FFI)")
        target_compile_options(interface_ffi PRIVATE -fprofile-instr-generate -fcoverage-mapping -g)
        target_link_options(interface_ffi PRIVATE -fprofile-instr-generate)
    endif ()

    #
    # --- FIPS JNI + FFI Libraries (no OPS / coverage instrumentation; see
    #     the FIPS source-list comment above). macOS two-level namespace
    #     binds each library's internal calls to its own copies, so no
    #     -Bsymbolic is needed here (unlike Linux).
    #
    add_library(interface_fips_jni SHARED ${FIPS_JNI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_fips_jni PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_jni PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_fips_jni PUBLIC JOSTLE_OPS)
    endif ()
    if (DEFINED ENV{JOSTLE_COVERAGE})
        target_compile_options(interface_fips_jni PRIVATE -fprofile-instr-generate -fcoverage-mapping -g)
        target_link_options(interface_fips_jni PRIVATE -fprofile-instr-generate)
    endif ()

    add_library(interface_fips_ffi SHARED ${FIPS_FFI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_fips_ffi PUBLIC JOSTLE_OPS)
    endif ()
    if (DEFINED ENV{JOSTLE_COVERAGE})
        target_compile_options(interface_fips_ffi PRIVATE -fprofile-instr-generate -fcoverage-mapping -g)
        target_link_options(interface_fips_ffi PRIVATE -fprofile-instr-generate)
    endif ()

    #
    # Resolver and deps structure
    #

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_jni DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_ffi DESTINATION ${INSTALL_PATH})
    install(FILES "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}" DESTINATION ${INSTALL_PATH})



elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux" AND
(
        ${BC_ARCH} STREQUAL "arm64" OR
        ${BC_ARCH} STREQUAL "aarch64" OR
        ${BC_ARCH} STREQUAL "x86_64" OR
        ${BC_ARCH} STREQUAL "s390x")
)

    #
    # Linux
    #
    SET(OPTIONS "-O3")
    if (${BC_ARCH} STREQUAL "x86_64" OR ${BC_ARCH} STREQUAL "s390x")
        SET(OPEN_SSL_LIB "lib64/libcrypto.so.3")
    else ()
        SET(OPEN_SSL_LIB "lib/libcrypto.so.3")
    endif ()

    SET(INSTALL_PATH "${JAVA_PRJ_HOME}/jostle/src/main/resources/native/linux/${BC_ARCH}/")
    SET(JNI_INCLUDE "${JAVA_HOME}/include/" "${JAVA_HOME}/include/linux" "${JAVA_PRJ_HOME}/jostle/build/generated/sources/headers/java/main")

    #
    # --- JNI Library
    #
    add_library(interface_jni SHARED
            nonfips/jni/md_jni.c
            nonfips/jni/rand_jni.c
            nonfips/jni/mac_jni.c
            nonfips/jni/native_info_jni.c
            nonfips/jni/open_ssl_jni.c
            nonfips/jni/block_cipher_ni_jni.c
            nonfips/jni/ccm_ni_jni.c
            nonfips/jni/spec_ni_jni.c
            nonfips/jni/mldsa_ni_jni.c
            nonfips/jni/slhdsa_ni_jni.c
            nonfips/jni/mlkem_ni_jni.c
            nonfips/jni/asn1_ni_jni.c
            nonfips/jni/ks_jni.c
            nonfips/util/block_cipher_ctx.h
            nonfips/util/block_cipher_ctx.c
            nonfips/util/ccm_ctx.h
            nonfips/util/ccm_ctx.c
            nonfips/util/bc_err_codes.h
            nonfips/jni/byte_array_critical.c
            nonfips/jni/byte_array_critical.h
            nonfips/util/mldsa.h
            nonfips/util/mldsa.c
            nonfips/util/slhdsa.h
            nonfips/util/slhdsa.c
            nonfips/util/mlkem.h
            nonfips/util/mlkem.c
            nonfips/util/encapdecap.h
            nonfips/util/encapdecap.c
            nonfips/util/ctr_u128_t.h
            nonfips/util/ctr_u128_t.c
            nonfips/jni/bytearrays.c
            nonfips/jni/bytearrays.h
            nonfips/util/key_spec.c
            nonfips/util/key_spec.h
            nonfips/util/asn1_util.c
            nonfips/util/asn1_util.h
            nonfips/util/ks.h
            nonfips/util/ks.c
            nonfips/util/ops.h
            nonfips/util/ops.c
            nonfips/jni/ops.c
            nonfips/jni/kdf_jni.c
            nonfips/util/kdf.h
            nonfips/util/kdf.c
            nonfips/util/mac.h
            nonfips/util/mac.c
            nonfips/util/md.c
            nonfips/util/md.h
            nonfips/util/rand.c
            nonfips/util/rand.h
            nonfips/util/rand/rand_upcall.h
            nonfips/util/rand/jostle_lib_ctx.h
            nonfips/util/rand/jostle_lib_ctx.c
            nonfips/jni/rand_upcall_jni.h
            nonfips/jni/rand_upcall_jni.c
            nonfips/jni/ed_jni.c
            nonfips/jni/rsa_ni_jni.c
            nonfips/jni/rsa_oaep_ni_jni.c
            nonfips/jni/rsa_pkcs1_ni_jni.c
            nonfips/jni/ec_ni_jni.c
            nonfips/jni/dsa_ni_jni.c
            nonfips/jni/dh_ni_jni.c
            nonfips/jni/xec_ni_jni.c
            nonfips/util/edec.h
            nonfips/util/edec.c
            nonfips/util/rsa.h
            nonfips/util/rsa.c
            nonfips/util/rsa_oaep.h
            nonfips/util/rsa_oaep.c
            nonfips/util/rsa_pkcs1.h
            nonfips/util/rsa_pkcs1.c
            nonfips/util/ec.h
            nonfips/util/ec.c
            nonfips/util/dsa.h
            nonfips/util/dsa.c
            nonfips/util/dh.h
            nonfips/util/dh.c
            nonfips/util/xec.h
            nonfips/util/xec.c
    )

    target_include_directories(interface_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_jni PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_jni PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        message("OPS Test Enabled")
        target_compile_definitions(interface_jni PUBLIC JOSTLE_OPS)
    endif ()

    # ---


    #
    # -- FFI Library
    #
    add_library(interface_ffi SHARED
            nonfips/ffi/md_ffi.c
            nonfips/ffi/rand_ffi.c
            nonfips/ffi/mac_ffi.c
            nonfips/ffi/ffi.h
            nonfips/ffi/ffi.c
            nonfips/ffi/types.h
            nonfips/ffi/native_info_ffi.h
            nonfips/ffi/native_info_ffi.c
            nonfips/ffi/openssl_ffi.h
            nonfips/ffi/openssl_ffi.c
            nonfips/ffi/block_cipher_ni_ffi.c
            nonfips/ffi/ccm_ni_ffi.c
            nonfips/ffi/spec_ni_ffi.c
            nonfips/ffi/mldsa_ni_ffi.c
            nonfips/ffi/slh_dsa_ni_ffi.c
            nonfips/ffi/mlkem_ni_ffi.c
            nonfips/ffi/asn1_ni_ffi.c
            nonfips/ffi/ks_ffi.c
            nonfips/util/jo_assert.h
            nonfips/util/mldsa.h
            nonfips/util/mldsa.c
            nonfips/util/slhdsa.h
            nonfips/util/slhdsa.c
            nonfips/util/mlkem.h
            nonfips/util/mlkem.c
            nonfips/util/encapdecap.h
            nonfips/util/encapdecap.c
            nonfips/util/block_cipher_ctx.h
            nonfips/util/block_cipher_ctx.c
            nonfips/util/ccm_ctx.h
            nonfips/util/ccm_ctx.c
            nonfips/util/ctr_u128_t.h
            nonfips/util/ctr_u128_t.c
            nonfips/util/bc_err_codes.h
            nonfips/util/key_spec.c
            nonfips/util/key_spec.h
            nonfips/util/asn1_util.c
            nonfips/util/asn1_util.h
            nonfips/util/ks.h
            nonfips/util/ks.c
            nonfips/util/ops.h
            nonfips/util/ops.c
            nonfips/ffi/kdf_ffi.c
            nonfips/util/kdf.h
            nonfips/util/kdf.c
            nonfips/util/mac.h
            nonfips/util/mac.c
            nonfips/util/md.c
            nonfips/util/md.h
            nonfips/util/rand.c
            nonfips/util/rand.h
            nonfips/util/rand/rand_upcall.h
            nonfips/util/rand/jostle_lib_ctx.h
            nonfips/util/rand/jostle_lib_ctx.c
            nonfips/ffi/rand_upcall_ffi.h
            nonfips/ffi/rand_upcall_ffi.c
            nonfips/util/edec.h
            nonfips/util/edec.c
            nonfips/util/rsa.h
            nonfips/util/rsa.c
            nonfips/util/rsa_oaep.h
            nonfips/util/rsa_oaep.c
            nonfips/util/rsa_pkcs1.h
            nonfips/util/rsa_pkcs1.c
            nonfips/util/ec.h
            nonfips/util/ec.c
            nonfips/util/dsa.h
            nonfips/util/dsa.c
            nonfips/util/dh.h
            nonfips/util/dh.c
            nonfips/util/xec.h
            nonfips/util/xec.c
            nonfips/ffi/ed_ni_ffi.c
            nonfips/ffi/rsa_ni_ffi.c
            nonfips/ffi/rsa_oaep_ni_ffi.c
            nonfips/ffi/rsa_pkcs1_ni_ffi.c
            nonfips/ffi/ec_ni_ffi.c
            nonfips/ffi/dsa_ni_ffi.c
            nonfips/ffi/dh_ni_ffi.c
            nonfips/ffi/xec_ni_ffi.c
    )

    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        message("OPS Test Enabled")
        target_compile_definitions(interface_ffi PUBLIC JOSTLE_OPS)
    endif ()

    #
    # --- FIPS JNI + FFI Libraries (no OPS / coverage instrumentation; see
    #     the FIPS source-list comment above). -Bsymbolic is REQUIRED here:
    #     with two interface libraries exporting the same util symbols, ELF
    #     load-order interposition would otherwise bind the FIPS library's
    #     internal calls to the base library's copies - silently running
    #     "FIPS" operations against the non-FIPS lib ctx. -Bsymbolic binds
    #     this library's references to its own definitions at link time.
    #
    add_library(interface_fips_jni SHARED ${FIPS_JNI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_fips_jni PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_jni PRIVATE -Wall -Wextra -Wpedantic -O3)
    target_link_options(interface_fips_jni PRIVATE -Wl,-Bsymbolic)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_fips_jni PUBLIC JOSTLE_OPS)
    endif ()

    add_library(interface_fips_ffi SHARED ${FIPS_FFI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    target_link_options(interface_fips_ffi PRIVATE -Wl,-Bsymbolic)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_fips_ffi PUBLIC JOSTLE_OPS)
    endif ()

    #
    # Resolver and deps structure
    #

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_jni DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_ffi DESTINATION ${INSTALL_PATH})
    install(FILES "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}" DESTINATION ${INSTALL_PATH})

elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")

    #
    # Windows
    #
    SET(OPTIONS "-O2")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    SET(OPEN_SSL_LIB "${OPENSSL_PREFIX}/lib64/libcrypto.lib")
    SET(OPEN_SSL_DLL "${OPENSSL_PREFIX}/lib64/libcrypto-3-x64.dll")
    SET(INSTALL_PATH "${JAVA_PRJ_HOME}/jostle/src/main/resources/native/windows/${BC_ARCH_RESOURCE}/")
    SET(JNI_INCLUDE "${JAVA_HOME}/include/" "${JAVA_HOME}/include/win32" "${JAVA_PRJ_HOME}/jostle/build/generated/sources/headers/java/main")

    add_library(interface_jni SHARED
            nonfips/jni/md_jni.c
            nonfips/jni/rand_jni.c
            nonfips/jni/mac_jni.c
            nonfips/jni/native_info_jni.c
            nonfips/jni/open_ssl_jni.c
            nonfips/jni/block_cipher_ni_jni.c
            nonfips/jni/ccm_ni_jni.c
            nonfips/jni/spec_ni_jni.c
            nonfips/jni/mldsa_ni_jni.c
            nonfips/jni/slhdsa_ni_jni.c
            nonfips/jni/mlkem_ni_jni.c
            nonfips/jni/asn1_ni_jni.c
            nonfips/jni/ks_jni.c
            nonfips/util/jo_assert.h
            nonfips/util/mldsa.h
            nonfips/util/mldsa.c
            nonfips/util/slhdsa.h
            nonfips/util/slhdsa.c
            nonfips/util/mlkem.h
            nonfips/util/mlkem.c
            nonfips/util/encapdecap.h
            nonfips/util/encapdecap.c
            nonfips/util/block_cipher_ctx.h
            nonfips/util/block_cipher_ctx.c
            nonfips/util/ccm_ctx.h
            nonfips/util/ccm_ctx.c
            nonfips/util/ctr_u128_t.h
            nonfips/util/ctr_u128_t.c
            nonfips/util/bc_err_codes.h
            nonfips/util/key_spec.c
            nonfips/util/key_spec.h
            nonfips/jni/byte_array_critical.c
            nonfips/jni/byte_array_critical.h
            nonfips/jni/bytearrays.c
            nonfips/jni/bytearrays.h
            nonfips/util/asn1_util.c
            nonfips/util/asn1_util.h
            nonfips/util/ks.h
            nonfips/util/ks.c
            nonfips/util/ops.h
            nonfips/util/ops.c
            nonfips/jni/ops.c
            nonfips/jni/kdf_jni.c
            nonfips/util/kdf.h
            nonfips/util/kdf.c
            nonfips/util/mac.h
            nonfips/util/mac.c
            nonfips/util/md.c
            nonfips/util/md.h
            nonfips/util/rand.c
            nonfips/util/rand.h
            nonfips/util/rand/rand_upcall.h
            nonfips/util/rand/jostle_lib_ctx.h
            nonfips/util/rand/jostle_lib_ctx.c
            nonfips/jni/rand_upcall_jni.h
            nonfips/jni/rand_upcall_jni.c
            nonfips/jni/ed_jni.c
            nonfips/jni/rsa_ni_jni.c
            nonfips/jni/rsa_oaep_ni_jni.c
            nonfips/jni/rsa_pkcs1_ni_jni.c
            nonfips/jni/ec_ni_jni.c
            nonfips/jni/dsa_ni_jni.c
            nonfips/jni/dh_ni_jni.c
            nonfips/jni/xec_ni_jni.c
            nonfips/util/edec.h
            nonfips/util/edec.c
            nonfips/util/rsa.h
            nonfips/util/rsa.c
            nonfips/util/rsa_oaep.h
            nonfips/util/rsa_oaep.c
            nonfips/util/rsa_pkcs1.h
            nonfips/util/rsa_pkcs1.c
            nonfips/util/ec.h
            nonfips/util/ec.c
            nonfips/util/dsa.h
            nonfips/util/dsa.c
            nonfips/util/dh.h
            nonfips/util/dh.c
            nonfips/util/xec.h
            nonfips/util/xec.c
    )

    target_include_directories(interface_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_jni PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_jni PRIVATE /W4 /O2)
    # HybridCRT: dynamic UCRT override, pairs with /MT from CMAKE_MSVC_RUNTIME_LIBRARY.
    target_link_options(interface_jni PRIVATE "/NODEFAULTLIB:libucrt.lib" "/DEFAULTLIB:ucrt.lib")
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_jni PUBLIC JOSTLE_OPS)
    endif ()

    add_library(interface_ffi SHARED
            nonfips/ffi/ffi.h
            nonfips/ffi/ffi.c
            nonfips/ffi/types.h
            nonfips/ffi/native_info_ffi.h
            nonfips/ffi/native_info_ffi.c
            nonfips/ffi/openssl_ffi.h
            nonfips/ffi/openssl_ffi.c
            nonfips/ffi/block_cipher_ni_ffi.c
            nonfips/ffi/ccm_ni_ffi.c
            nonfips/ffi/spec_ni_ffi.c
            nonfips/ffi/mldsa_ni_ffi.c
            nonfips/ffi/mlkem_ni_ffi.c
            nonfips/ffi/slh_dsa_ni_ffi.c
            nonfips/ffi/asn1_ni_ffi.c
            nonfips/ffi/md_ffi.c
            nonfips/ffi/rand_ffi.c
            nonfips/ffi/mac_ffi.c
            nonfips/ffi/ks_ffi.c
            nonfips/util/jo_assert.h
            nonfips/util/mldsa.h
            nonfips/util/mldsa.c
            nonfips/util/slhdsa.h
            nonfips/util/slhdsa.c
            nonfips/util/mlkem.h
            nonfips/util/mlkem.c
            nonfips/util/encapdecap.h
            nonfips/util/encapdecap.c
            nonfips/util/block_cipher_ctx.h
            nonfips/util/block_cipher_ctx.c
            nonfips/util/ccm_ctx.h
            nonfips/util/ccm_ctx.c
            nonfips/util/ctr_u128_t.h
            nonfips/util/ctr_u128_t.c
            nonfips/util/bc_err_codes.h
            nonfips/util/key_spec.c
            nonfips/util/key_spec.h
            nonfips/util/asn1_util.c
            nonfips/util/asn1_util.h
            nonfips/util/ks.h
            nonfips/util/ks.c
            nonfips/util/ops.h
            nonfips/util/ops.c
            nonfips/ffi/kdf_ffi.c
            nonfips/util/kdf.h
            nonfips/util/kdf.c
            nonfips/util/mac.h
            nonfips/util/mac.c
            nonfips/util/md.c
            nonfips/util/md.h
            nonfips/util/rand.c
            nonfips/util/rand.h
            nonfips/util/rand/rand_upcall.h
            nonfips/util/rand/jostle_lib_ctx.h
            nonfips/util/rand/jostle_lib_ctx.c
            nonfips/ffi/rand_upcall_ffi.h
            nonfips/ffi/rand_upcall_ffi.c
            nonfips/util/edec.h
            nonfips/util/edec.c
            nonfips/util/rsa.h
            nonfips/util/rsa.c
            nonfips/util/rsa_oaep.h
            nonfips/util/rsa_oaep.c
            nonfips/util/rsa_pkcs1.h
            nonfips/util/rsa_pkcs1.c
            nonfips/util/ec.h
            nonfips/util/ec.c
            nonfips/util/dsa.h
            nonfips/util/dsa.c
            nonfips/util/dh.h
            nonfips/util/dh.c
            nonfips/util/xec.h
            nonfips/util/xec.c
            nonfips/ffi/ed_ni_ffi.c
            nonfips/ffi/rsa_ni_ffi.c
            nonfips/ffi/rsa_oaep_ni_ffi.c
            nonfips/ffi/rsa_pkcs1_ni_ffi.c
            nonfips/ffi/ec_ni_ffi.c
            nonfips/ffi/dsa_ni_ffi.c
            nonfips/ffi/dh_ni_ffi.c
            nonfips/ffi/xec_ni_ffi.c

    )

    set_target_properties(interface_ffi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE /W4 /O2)
    # HybridCRT: dynamic UCRT override, pairs with /MT from CMAKE_MSVC_RUNTIME_LIBRARY.
    target_link_options(interface_ffi PRIVATE "/NODEFAULTLIB:libucrt.lib" "/DEFAULTLIB:ucrt.lib")
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_ffi PUBLIC JOSTLE_OPS)
    endif ()

    #
    # --- FIPS JNI + FFI Libraries (no OPS instrumentation; see the FIPS
    #     source-list comment above). PE imports bind per-DLL, so Windows
    #     has no cross-library interposition concern.
    #
    add_library(interface_fips_jni SHARED ${FIPS_JNI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_fips_jni PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_jni PRIVATE /W4 /O2)
    # HybridCRT: dynamic UCRT override, pairs with /MT from CMAKE_MSVC_RUNTIME_LIBRARY.
    # Must match the non-FIPS libs and OpenSSL so all shipped DLLs share ucrtbase's heap.
    target_link_options(interface_fips_jni PRIVATE "/NODEFAULTLIB:libucrt.lib" "/DEFAULTLIB:ucrt.lib")
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_fips_jni PUBLIC JOSTLE_OPS)
    endif ()

    add_library(interface_fips_ffi SHARED ${FIPS_FFI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    set_target_properties(interface_fips_ffi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_include_directories(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_fips_ffi PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_ffi PRIVATE /W4 /O2)
    # HybridCRT: dynamic UCRT override, pairs with /MT from CMAKE_MSVC_RUNTIME_LIBRARY.
    # Must match the non-FIPS libs and OpenSSL so all shipped DLLs share ucrtbase's heap.
    target_link_options(interface_fips_ffi PRIVATE "/NODEFAULTLIB:libucrt.lib" "/DEFAULTLIB:ucrt.lib")
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_fips_ffi PUBLIC JOSTLE_OPS)
    endif ()

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_jni RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_ffi RUNTIME DESTINATION ${INSTALL_PATH})
    install(FILES "${OPEN_SSL_DLL}" DESTINATION ${INSTALL_PATH})

endif ()

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
# The FIPS targets carry no JOSTLE_OPS / JOSTLE_COVERAGE instrumentation:
# operations-test fault injection must not ship inside the FIPS interface
# library.
#
set(FIPS_UTIL_SOURCES
        util/jo_assert.h
        util/mldsa.h
        util/mldsa.c
        util/slhdsa.h
        util/slhdsa.c
        util/mlkem.h
        util/mlkem.c
        util/encapdecap.h
        util/encapdecap.c
        util/block_cipher_ctx.h
        util/block_cipher_ctx.c
        util/ccm_ctx.h
        util/ccm_ctx.c
        util/ctr_u128_t.h
        util/ctr_u128_t.c
        util/bc_err_codes.h
        util/key_spec.c
        util/key_spec.h
        util/asn1_util.c
        util/asn1_util.h
        util/ks.h
        util/ks.c
        util/ops.h
        util/ops.c
        util/kdf.h
        util/kdf.c
        util/mac.h
        util/mac.c
        util/md.c
        util/md.h
        util/rand.c
        util/rand.h
        util/rand/rand_upcall.h
        util/rand/jostle_lib_ctx.h
        util/rand/jostle_lib_ctx.c
        util/rand/jostle_fips_ctx.h
        util/rand/jostle_fips_ctx.c
        util/edec.h
        util/edec.c
        util/rsa.h
        util/rsa.c
        util/rsa_oaep.h
        util/rsa_oaep.c
        util/rsa_pkcs1.h
        util/rsa_pkcs1.c
        util/ec.h
        util/ec.c
        util/dsa.h
        util/dsa.c
        util/dh.h
        util/dh.c
        util/xec.h
        util/xec.c
)

set(FIPS_JNI_GLUE_SOURCES
        jni/openssl_fips_jni.c
        jni/md_fips_jni.c
        jni/block_cipher_fips_jni.c
        jni/ccm_fips_jni.c
        jni/mac_fips_jni.c
        jni/rand_fips_jni.c
        jni/spec_fips_jni.c
        jni/asn1_fips_jni.c
        jni/rsa_fips_jni.c
        jni/rsa_oaep_fips_jni.c
        jni/rsa_pkcs1_fips_jni.c
        jni/rand_upcall_jni.h
        jni/rand_upcall_jni.c
        jni/byte_array_critical.c
        jni/byte_array_critical.h
        jni/bytearrays.c
        jni/bytearrays.h
)

set(FIPS_FFI_GLUE_SOURCES
        ffi/md_ffi.c
        ffi/rand_ffi.c
        ffi/mac_ffi.c
        ffi/ffi.h
        ffi/ffi.c
        ffi/types.h
        ffi/native_info_ffi.h
        ffi/native_info_ffi.c
        ffi/openssl_ffi.h
        ffi/openssl_ffi.c
        ffi/openssl_fips_ffi.h
        ffi/openssl_fips_ffi.c
        ffi/block_cipher_ni_ffi.c
        ffi/ccm_ni_ffi.c
        ffi/spec_ni_ffi.c
        ffi/mldsa_ni_ffi.c
        ffi/mlkem_ni_ffi.c
        ffi/slh_dsa_ni_ffi.c
        ffi/asn1_ni_ffi.c
        ffi/ks_ffi.c
        ffi/kdf_ffi.c
        ffi/rand_upcall_ffi.h
        ffi/rand_upcall_ffi.c
        ffi/ed_ni_ffi.c
        ffi/rsa_ni_ffi.c
        ffi/rsa_oaep_ni_ffi.c
        ffi/rsa_pkcs1_ni_ffi.c
        ffi/ec_ni_ffi.c
        ffi/dsa_ni_ffi.c
        ffi/dh_ni_ffi.c
        ffi/xec_ni_ffi.c
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
            jni/md_jni.c
            jni/rand_jni.c
            jni/mac_jni.c
            jni/native_info_jni.c
            jni/open_ssl_jni.c
            jni/block_cipher_ni_jni.c
            jni/ccm_ni_jni.c
            jni/spec_ni_jni.c
            jni/mldsa_ni_jni.c
            jni/slhdsa_ni_jni.c
            jni/mlkem_ni_jni.c
            jni/asn1_ni_jni.c
            jni/ks_jni.c
            util/jo_assert.h
            util/mldsa.h
            util/mldsa.c
            util/slhdsa.h
            util/slhdsa.c
            util/mlkem.h
            util/mlkem.c
            util/encapdecap.h
            util/encapdecap.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
            util/ccm_ctx.h
            util/ccm_ctx.c
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            jni/byte_array_critical.c
            jni/byte_array_critical.h
            jni/bytearrays.c
            jni/bytearrays.h
            util/asn1_util.c
            util/asn1_util.h
            util/ks.h
            util/ks.c
            util/ops.h
            util/ops.c
            jni/ops.c
            jni/kdf_jni.c
            util/kdf.h
            util/kdf.c
            util/mac.h
            util/mac.c
            util/md.c
            util/md.h
            util/rand.c
            util/rand.h
            util/rand/rand_upcall.h
            util/rand/jostle_lib_ctx.h
            util/rand/jostle_lib_ctx.c
            util/rand/jostle_fips_ctx.h
            util/rand/jostle_fips_ctx.c
            jni/rand_upcall_jni.h
            jni/rand_upcall_jni.c
            jni/ed_jni.c
            jni/rsa_ni_jni.c
            jni/rsa_oaep_ni_jni.c
            jni/rsa_pkcs1_ni_jni.c
            jni/ec_ni_jni.c
            jni/dsa_ni_jni.c
            jni/dh_ni_jni.c
            jni/xec_ni_jni.c
            util/edec.h
            util/edec.c
            util/rsa.h
            util/rsa.c
            util/rsa_oaep.h
            util/rsa_oaep.c
            util/rsa_pkcs1.h
            util/rsa_pkcs1.c
            util/ec.h
            util/ec.c
            util/dsa.h
            util/dsa.c
            util/dh.h
            util/dh.c
            util/xec.h
            util/xec.c
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
            ffi/md_ffi.c
            ffi/rand_ffi.c
            ffi/mac_ffi.c
            ffi/ffi.h
            ffi/ffi.c
            ffi/types.h
            ffi/native_info_ffi.h
            ffi/native_info_ffi.c
            ffi/openssl_ffi.h
            ffi/openssl_ffi.c
            ffi/block_cipher_ni_ffi.c
            ffi/ccm_ni_ffi.c
            ffi/spec_ni_ffi.c
            ffi/mldsa_ni_ffi.c
            ffi/mlkem_ni_ffi.c
            ffi/slh_dsa_ni_ffi.c
            ffi/asn1_ni_ffi.c
            ffi/ks_ffi.c
            util/jo_assert.h
            util/mldsa.h
            util/mldsa.c
            util/slhdsa.h
            util/slhdsa.c
            util/mlkem.h
            util/mlkem.c
            util/encapdecap.h
            util/encapdecap.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
            util/ccm_ctx.h
            util/ccm_ctx.c
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ks.h
            util/ks.c
            util/ops.h
            util/ops.c
            ffi/kdf_ffi.c
            util/kdf.h
            util/kdf.c
            util/mac.h
            util/mac.c
            util/md.c
            util/md.h
            util/rand.c
            util/rand.h
            util/rand/rand_upcall.h
            util/rand/jostle_lib_ctx.h
            util/rand/jostle_lib_ctx.c
            util/rand/jostle_fips_ctx.h
            util/rand/jostle_fips_ctx.c
            ffi/rand_upcall_ffi.h
            ffi/rand_upcall_ffi.c
            ffi/ed_ni_ffi.c
            ffi/rsa_ni_ffi.c
            ffi/rsa_oaep_ni_ffi.c
            ffi/rsa_pkcs1_ni_ffi.c
            ffi/ec_ni_ffi.c
            ffi/dsa_ni_ffi.c
            ffi/dh_ni_ffi.c
            ffi/xec_ni_ffi.c
            util/edec.h
            util/edec.c
            util/rsa.h
            util/rsa.c
            util/rsa_oaep.h
            util/rsa_oaep.c
            util/rsa_pkcs1.h
            util/rsa_pkcs1.c
            util/ec.h
            util/ec.c
            util/dsa.h
            util/dsa.c
            util/dh.h
            util/dh.c
            util/xec.h
            util/xec.c
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

    add_library(interface_fips_ffi SHARED ${FIPS_FFI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)

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
            jni/md_jni.c
            jni/rand_jni.c
            jni/mac_jni.c
            jni/native_info_jni.c
            jni/open_ssl_jni.c
            jni/block_cipher_ni_jni.c
            jni/ccm_ni_jni.c
            jni/spec_ni_jni.c
            jni/mldsa_ni_jni.c
            jni/slhdsa_ni_jni.c
            jni/mlkem_ni_jni.c
            jni/asn1_ni_jni.c
            jni/ks_jni.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
            util/ccm_ctx.h
            util/ccm_ctx.c
            util/bc_err_codes.h
            jni/byte_array_critical.c
            jni/byte_array_critical.h
            util/mldsa.h
            util/mldsa.c
            util/slhdsa.h
            util/slhdsa.c
            util/mlkem.h
            util/mlkem.c
            util/encapdecap.h
            util/encapdecap.c
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            jni/bytearrays.c
            jni/bytearrays.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ks.h
            util/ks.c
            util/ops.h
            util/ops.c
            jni/ops.c
            jni/kdf_jni.c
            util/kdf.h
            util/kdf.c
            util/mac.h
            util/mac.c
            util/md.c
            util/md.h
            util/rand.c
            util/rand.h
            util/rand/rand_upcall.h
            util/rand/jostle_lib_ctx.h
            util/rand/jostle_lib_ctx.c
            util/rand/jostle_fips_ctx.h
            util/rand/jostle_fips_ctx.c
            jni/rand_upcall_jni.h
            jni/rand_upcall_jni.c
            jni/ed_jni.c
            jni/rsa_ni_jni.c
            jni/rsa_oaep_ni_jni.c
            jni/rsa_pkcs1_ni_jni.c
            jni/ec_ni_jni.c
            jni/dsa_ni_jni.c
            jni/dh_ni_jni.c
            jni/xec_ni_jni.c
            util/edec.h
            util/edec.c
            util/rsa.h
            util/rsa.c
            util/rsa_oaep.h
            util/rsa_oaep.c
            util/rsa_pkcs1.h
            util/rsa_pkcs1.c
            util/ec.h
            util/ec.c
            util/dsa.h
            util/dsa.c
            util/dh.h
            util/dh.c
            util/xec.h
            util/xec.c
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
            ffi/md_ffi.c
            ffi/rand_ffi.c
            ffi/mac_ffi.c
            ffi/ffi.h
            ffi/ffi.c
            ffi/types.h
            ffi/native_info_ffi.h
            ffi/native_info_ffi.c
            ffi/openssl_ffi.h
            ffi/openssl_ffi.c
            ffi/block_cipher_ni_ffi.c
            ffi/ccm_ni_ffi.c
            ffi/spec_ni_ffi.c
            ffi/mldsa_ni_ffi.c
            ffi/slh_dsa_ni_ffi.c
            ffi/mlkem_ni_ffi.c
            ffi/asn1_ni_ffi.c
            ffi/ks_ffi.c
            util/jo_assert.h
            util/mldsa.h
            util/mldsa.c
            util/slhdsa.h
            util/slhdsa.c
            util/mlkem.h
            util/mlkem.c
            util/encapdecap.h
            util/encapdecap.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
            util/ccm_ctx.h
            util/ccm_ctx.c
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ks.h
            util/ks.c
            util/ops.h
            util/ops.c
            ffi/kdf_ffi.c
            util/kdf.h
            util/kdf.c
            util/mac.h
            util/mac.c
            util/md.c
            util/md.h
            util/rand.c
            util/rand.h
            util/rand/rand_upcall.h
            util/rand/jostle_lib_ctx.h
            util/rand/jostle_lib_ctx.c
            util/rand/jostle_fips_ctx.h
            util/rand/jostle_fips_ctx.c
            ffi/rand_upcall_ffi.h
            ffi/rand_upcall_ffi.c
            util/edec.h
            util/edec.c
            util/rsa.h
            util/rsa.c
            util/rsa_oaep.h
            util/rsa_oaep.c
            util/rsa_pkcs1.h
            util/rsa_pkcs1.c
            util/ec.h
            util/ec.c
            util/dsa.h
            util/dsa.c
            util/dh.h
            util/dh.c
            util/xec.h
            util/xec.c
            ffi/ed_ni_ffi.c
            ffi/rsa_ni_ffi.c
            ffi/rsa_oaep_ni_ffi.c
            ffi/rsa_pkcs1_ni_ffi.c
            ffi/ec_ni_ffi.c
            ffi/dsa_ni_ffi.c
            ffi/dh_ni_ffi.c
            ffi/xec_ni_ffi.c
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

    add_library(interface_fips_ffi SHARED ${FIPS_FFI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    target_include_directories(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    target_link_options(interface_fips_ffi PRIVATE -Wl,-Bsymbolic)

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
    SET(OPEN_SSL_LIB "${OPENSSL_PREFIX}/lib64/libcrypto.lib")
    SET(OPEN_SSL_DLL "${OPENSSL_PREFIX}/lib64/libcrypto-3-x64.dll")
    SET(INSTALL_PATH "${JAVA_PRJ_HOME}/jostle/src/main/resources/native/windows/${BC_ARCH_RESOURCE}/")
    SET(JNI_INCLUDE "${JAVA_HOME}/include/" "${JAVA_HOME}/include/win32" "${JAVA_PRJ_HOME}/jostle/build/generated/sources/headers/java/main")

    add_library(interface_jni SHARED
            jni/md_jni.c
            jni/rand_jni.c
            jni/mac_jni.c
            jni/native_info_jni.c
            jni/open_ssl_jni.c
            jni/block_cipher_ni_jni.c
            jni/ccm_ni_jni.c
            jni/spec_ni_jni.c
            jni/mldsa_ni_jni.c
            jni/slhdsa_ni_jni.c
            jni/mlkem_ni_jni.c
            jni/asn1_ni_jni.c
            jni/ks_jni.c
            util/jo_assert.h
            util/mldsa.h
            util/mldsa.c
            util/slhdsa.h
            util/slhdsa.c
            util/mlkem.h
            util/mlkem.c
            util/encapdecap.h
            util/encapdecap.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
            util/ccm_ctx.h
            util/ccm_ctx.c
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            jni/byte_array_critical.c
            jni/byte_array_critical.h
            jni/bytearrays.c
            jni/bytearrays.h
            util/asn1_util.c
            util/asn1_util.h
            util/ks.h
            util/ks.c
            util/ops.h
            util/ops.c
            jni/ops.c
            jni/kdf_jni.c
            util/kdf.h
            util/kdf.c
            util/mac.h
            util/mac.c
            util/md.c
            util/md.h
            util/rand.c
            util/rand.h
            util/rand/rand_upcall.h
            util/rand/jostle_lib_ctx.h
            util/rand/jostle_lib_ctx.c
            util/rand/jostle_fips_ctx.h
            util/rand/jostle_fips_ctx.c
            jni/rand_upcall_jni.h
            jni/rand_upcall_jni.c
            jni/ed_jni.c
            jni/rsa_ni_jni.c
            jni/rsa_oaep_ni_jni.c
            jni/rsa_pkcs1_ni_jni.c
            jni/ec_ni_jni.c
            jni/dsa_ni_jni.c
            jni/dh_ni_jni.c
            jni/xec_ni_jni.c
            util/edec.h
            util/edec.c
            util/rsa.h
            util/rsa.c
            util/rsa_oaep.h
            util/rsa_oaep.c
            util/rsa_pkcs1.h
            util/rsa_pkcs1.c
            util/ec.h
            util/ec.c
            util/dsa.h
            util/dsa.c
            util/dh.h
            util/dh.c
            util/xec.h
            util/xec.c
    )

    target_include_directories(interface_jni PUBLIC "${OPENSSL_PREFIX}/include" "${JNI_INCLUDE}")
    target_link_libraries(interface_jni PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_jni PRIVATE /W4 /O2)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_jni PUBLIC JOSTLE_OPS)
    endif ()

    add_library(interface_ffi SHARED
            ffi/ffi.h
            ffi/ffi.c
            ffi/types.h
            ffi/native_info_ffi.h
            ffi/native_info_ffi.c
            ffi/openssl_ffi.h
            ffi/openssl_ffi.c
            ffi/block_cipher_ni_ffi.c
            ffi/ccm_ni_ffi.c
            ffi/spec_ni_ffi.c
            ffi/mldsa_ni_ffi.c
            ffi/mlkem_ni_ffi.c
            ffi/slh_dsa_ni_ffi.c
            ffi/asn1_ni_ffi.c
            ffi/md_ffi.c
            ffi/rand_ffi.c
            ffi/mac_ffi.c
            ffi/ks_ffi.c
            util/jo_assert.h
            util/mldsa.h
            util/mldsa.c
            util/slhdsa.h
            util/slhdsa.c
            util/mlkem.h
            util/mlkem.c
            util/encapdecap.h
            util/encapdecap.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
            util/ccm_ctx.h
            util/ccm_ctx.c
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ks.h
            util/ks.c
            util/ops.h
            util/ops.c
            ffi/kdf_ffi.c
            util/kdf.h
            util/kdf.c
            util/mac.h
            util/mac.c
            util/md.c
            util/md.h
            util/rand.c
            util/rand.h
            util/rand/rand_upcall.h
            util/rand/jostle_lib_ctx.h
            util/rand/jostle_lib_ctx.c
            util/rand/jostle_fips_ctx.h
            util/rand/jostle_fips_ctx.c
            ffi/rand_upcall_ffi.h
            ffi/rand_upcall_ffi.c
            util/edec.h
            util/edec.c
            util/rsa.h
            util/rsa.c
            util/rsa_oaep.h
            util/rsa_oaep.c
            util/rsa_pkcs1.h
            util/rsa_pkcs1.c
            util/ec.h
            util/ec.c
            util/dsa.h
            util/dsa.c
            util/dh.h
            util/dh.c
            util/xec.h
            util/xec.c
            ffi/ed_ni_ffi.c
            ffi/rsa_ni_ffi.c
            ffi/rsa_oaep_ni_ffi.c
            ffi/rsa_pkcs1_ni_ffi.c
            ffi/ec_ni_ffi.c
            ffi/dsa_ni_ffi.c
            ffi/dh_ni_ffi.c
            ffi/xec_ni_ffi.c

    )

    set_target_properties(interface_ffi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE /W4 /O2)
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

    add_library(interface_fips_ffi SHARED ${FIPS_FFI_GLUE_SOURCES} ${FIPS_UTIL_SOURCES})
    set_target_properties(interface_fips_ffi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_include_directories(interface_fips_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_fips_ffi PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_fips_ffi PRIVATE /W4 /O2)

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_jni RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_fips_ffi RUNTIME DESTINATION ${INSTALL_PATH})
    install(FILES "${OPEN_SSL_DLL}" DESTINATION ${INSTALL_PATH})

endif ()

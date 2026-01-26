#
#  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
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

# Normalize architecture naming for resource folder layout.
# (On Windows, CMAKE_SYSTEM_PROCESSOR is commonly "AMD64" but resources use "amd64".)
set(BC_ARCH_RESOURCE "${BC_ARCH}")
string(TOLOWER "${BC_ARCH_RESOURCE}" BC_ARCH_RESOURCE)
if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    if (BC_ARCH_RESOURCE STREQUAL "x86_64")
        # Keep as-is (some toolchains report x86_64).
    elseif (BC_ARCH_RESOURCE STREQUAL "amd64")
        # Keep as-is.
    elseif (BC_ARCH_RESOURCE STREQUAL "x64")
        set(BC_ARCH_RESOURCE "amd64")
    elseif (BC_ARCH_RESOURCE STREQUAL "x86-64")
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


if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" AND ${BC_ARCH} STREQUAL "arm64")


    #
    # OSX
    #


    SET(OPTIONS "-O3")
    SET(OPEN_SSL_LIB "/lib/libcrypto.3.dylib")
    SET(INSTALL_PATH "${JAVA_PRJ_HOME}/jostle/src/main/resources/native/osx/arm64/")
    SET(JNI_INCLUDE "${JAVA_HOME}/include/" "${JAVA_HOME}/include/darwin" "${JAVA_PRJ_HOME}/jostle/build/generated/sources/headers/java/main")

    #
    # --- JNI Library
    #
    add_library(interface_jni SHARED
            jni/native_info_jni.c
            jni/open_ssl_jni.c
            jni/block_cipher_ni_jni.c
            jni/spec_ni_jni.c
            jni/mldsa_ni_jni.c
            jni/slhdsa_ni_jni.c
            jni/mlkem_ni_jni.c
            jni/asn1_ni_jni.c
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
            util/ops.h
            util/ops.c
            jni/ops.c
            jni/kdf_jni.c
            util/kdf.h
            util/kdf.c

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
            ffi/ffi.h
            ffi/ffi.c
            ffi/types.h
            ffi/native_info_ffi.h
            ffi/native_info_ffi.c
            ffi/openssl_ffi.h
            ffi/openssl_ffi.c
            ffi/block_cipher_ni_ffi.c
            ffi/spec_ni_ffi.c
            ffi/mldsa_ni_ffi.c
            ffi/mlkem_ni_ffi.c
            ffi/slh_dsa_ni_ffi.c
            ffi/asn1_ni_ffi.c
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
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ops.h
            util/ops.c
            ffi/kdf_ffi.c
            util/kdf.h
            util/kdf.c
    )
    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        message("OPS Test Enabled")
        target_compile_definitions(interface_ffi PUBLIC JOSTLE_OPS)
    endif ()

    #
    # Resolver and deps structure
    #

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi DESTINATION ${INSTALL_PATH})
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
            jni/native_info_jni.c
            jni/open_ssl_jni.c
            jni/block_cipher_ni_jni.c
            jni/spec_ni_jni.c
            jni/mldsa_ni_jni.c
            jni/slhdsa_ni_jni.c
            jni/mlkem_ni_jni.c
            jni/asn1_ni_jni.c
            util/block_cipher_ctx.h
            util/block_cipher_ctx.c
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
            util/ops.h
            util/ops.c
            jni/ops.c
            jni/kdf_jni.c
            util/kdf.h
            util/kdf.c
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
            ffi/ffi.h
            ffi/ffi.c
            ffi/types.h
            ffi/native_info_ffi.h
            ffi/native_info_ffi.c
            ffi/openssl_ffi.h
            ffi/openssl_ffi.c
            ffi/block_cipher_ni_ffi.c
            ffi/spec_ni_ffi.c
            ffi/mldsa_ni_ffi.c
            ffi/slh_dsa_ni_ffi.c
            ffi/mlkem_ni_ffi.c
            ffi/asn1_ni_ffi.c
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
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ops.h
            util/ops.c
            ffi/kdf_ffi.c
            util/kdf.h
            util/kdf.c
    )

    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPENSSL_PREFIX}/${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE -Wall -Wextra -Wpedantic -O3)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        message("OPS Test Enabled")
        target_compile_definitions(interface_ffi PUBLIC JOSTLE_OPS)
    endif ()

    #
    # Resolver and deps structure
    #

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi DESTINATION ${INSTALL_PATH})
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
            jni/native_info_jni.c
            jni/open_ssl_jni.c
            jni/block_cipher_ni_jni.c
            jni/spec_ni_jni.c
            jni/mldsa_ni_jni.c
            jni/slhdsa_ni_jni.c
            jni/mlkem_ni_jni.c
            jni/asn1_ni_jni.c
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
            util/ops.h
            util/ops.c
            jni/ops.c
            jni/kdf_jni.c
            util/kdf.h
            util/kdf.c
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
            ffi/spec_ni_ffi.c
            ffi/mldsa_ni_ffi.c
            ffi/mlkem_ni_ffi.c
            ffi/slh_dsa_ni_ffi.c
            ffi/asn1_ni_ffi.c
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
            util/ctr_u128_t.h
            util/ctr_u128_t.c
            util/bc_err_codes.h
            util/key_spec.c
            util/key_spec.h
            util/asn1_util.c
            util/asn1_util.h
            util/ops.h
            util/ops.c
            ffi/kdf_ffi.c
            util/kdf.h
            util/kdf.c
    )

    set_target_properties(interface_ffi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

    target_include_directories(interface_ffi PUBLIC "${OPENSSL_PREFIX}/include")
    target_link_libraries(interface_ffi PUBLIC "${OPEN_SSL_LIB}")
    target_compile_options(interface_ffi PRIVATE /W4 /O2)
    if (DEFINED ENV{JOSTLE_OPS_TEST})
        target_compile_definitions(interface_ffi PUBLIC JOSTLE_OPS)
    endif ()

    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/loading/native" DESTINATION "${JAVA_PRJ_HOME}/jostle/src/main/resources")
    install(TARGETS interface_jni RUNTIME DESTINATION ${INSTALL_PATH})
    install(TARGETS interface_ffi RUNTIME DESTINATION ${INSTALL_PATH})
    install(FILES "${OPEN_SSL_DLL}" DESTINATION ${INSTALL_PATH})

endif ()




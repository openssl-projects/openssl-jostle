@echo off
setlocal enableextensions

set "SCRIPT_DIR=%~dp0"

if "%JAVA_HOME%"=="" (
	echo JAVA_HOME is unset; it should point to a Java 25 JDK installation.
	exit /b 1
)

if "%OPENSSL_PREFIX%"=="" (
	echo OPENSSL_PREFIX is unset; it should point to your OpenSSL install prefix.
	exit /b 1
)

where cmake >nul 2>nul
if errorlevel 1 (
	echo cmake not found on PATH.
	exit /b 1
)

where ninja >nul 2>nul
if errorlevel 1 (
	echo ninja not found on PATH. Install Ninja or ensure it is on PATH.
	exit /b 1
)

where clang-cl >nul 2>nul
if errorlevel 1 (
	echo clang-cl not found on PATH. Install LLVM and ensure clang-cl is on PATH.
	exit /b 1
)

pushd "%SCRIPT_DIR%" || exit /b 1

if exist build (
	echo Removing existing build directory...
	rmdir /s /q build
	if errorlevel 1 exit /b 1
)

mkdir build
if errorlevel 1 exit /b 1

pushd build || exit /b 1

cmake -DCMAKE_BUILD_TYPE=Release -G "Ninja" -DCMAKE_C_COMPILER=clang-cl ..
if errorlevel 1 exit /b 1

cmake --build . --config Release
if errorlevel 1 exit /b 1

cmake --install . --config Release
if errorlevel 1 exit /b 1

popd
popd

endlocal

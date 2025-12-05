# The OpenSSL JOSTLE Project

[![.github/workflows/arm.yaml](https://github.com/openssl-projects/openssl-jostle/actions/workflows/arm.yaml/badge.svg)](https://github.com/openssl-projects/openssl-jostle/actions/workflows/arm.yaml)
[![.github/workflows/intel.yaml](https://github.com/openssl-projects/openssl-jostle/actions/workflows/intel.yaml/badge.svg)](https://github.com/openssl-projects/openssl-jostle/actions/workflows/intel.yaml)

OpenSSL Jostle is a Java provider that uses the [OpenSSL Library](https://openssl-library.org/) for the cryptographic implementation.

This is a collaboration between the [OpenSSL Corporation](https://openssl-corporation.org/) and
the [Legion of the Bouncy Castle](https://bouncycastle.org/). This project wraps features of OpenSSL native library into a
standard Java JCA/JCE Provider.

The JOSTLE code base is released under the same license as the [OpenSSL Library](https://openssl-library.org/) - i.e. [Apache License 2.0](https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE). 

OpenSSL Jostle supports running on Java 1.8 to Java 25, and requires [Java 25](https://jdk.java.net/25/) to build.

## Usage

This section will be updated when there are published in maven central or equivalent.
For the time being you will need to build OpenSSL Jostle before you can try it out.

## Building

In this example we are going to build OpenSSL Jostle on an Intel machine spun up in AWS EC2.

### Building Locally + General Information

Building may present complexities.

Building involves generating the interface binaries and then installing those binaries and, potentially,
the OpenSSL Library libraries into the ```src/main/resources``` directory of the ```jostle``` Java project so
that they can ultimately be bundled into a single jar file.

The interface libraries are organised by common os name then architecture, eg "osx/arm64". The base directory
structure for this is laid out in ```interface/loading``` along with appropriately configured dependency
"deps.txt" files.


### Step 1 Obtain and build OpenSSL Library 3.5

OpenSSL Library 3.5 source bundle can be downloaded from [OpenSSL Downloads](https://openssl-library.org/source/)

After copying the source url, download the source tarball onto a suitable machine and unpack it.
For the current LTS release you can use the following commands.

```
    wget https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
    
    tar -zxvf openssl-3.5.4.tar.gz    
```

In order to build OpenSSL 3.5 you will need to have also installed the appropriate build tools for the OS that you are building on.

### Step 2 Build OpenSSL Library 3.5 

Users should specify a prefix when building the OpenSSL Library for this example there is no need to install it on the host 
for all users so we will use prefix and keep it nearby. 

```
  cd openssl-3.5.4
  
  # Tell OpenSSL to install build products in the same parent as openssl-3.5.4
  ./Configure --prefix=`pwd`/../openssl_3_5
  
  # Build it.
  make clean
  make
  make install_sw  
   
   
```

When the OpenSSL Library build finishes you should have the build artefacts available in ```../openssl_3_5```

For example, it should look something like this.

```

cd ..
ls -al
    
drwxr-xr-x.  4 ec2-user ec2-user    46 Oct  2 08:08 .
drwx------.  4 ec2-user ec2-user   133 Oct  2 07:34 ..
drwxr-xr-x. 28 ec2-user ec2-user 16384 Oct  2 08:08 openssl-3.5.4
drwxr-xr-x.  5 ec2-user ec2-user    45 Oct  2 08:08 openssl_3_5

ls -al openssl_3_5

drwxr-xr-x. 5 ec2-user ec2-user  45 Oct  2 08:08 .
drwxr-xr-x. 4 ec2-user ec2-user  46 Oct  2 08:08 ..
drwxr-xr-x. 2 ec2-user ec2-user  37 Oct  2 08:08 bin
drwxr-xr-x. 3 ec2-user ec2-user  21 Oct  2 08:08 include
drwxr-xr-x. 6 ec2-user ec2-user 186 Oct  2 08:08 lib64

```

Lastly we need to set the ```OPENSSL_PREFIX``` env var, this variable will be used by the 
OpenSSL Jostle build to locate the OpenSSL libraries.

```
cd openssl_3_5/
export OPENSSL_PREFIX=`pwd`

# Print it out.

echo "${OPENSSL_PREFIX}"
/home/ec2-user/build/openssl_3_5

```

### Step 3. Compile Headers
This step produces the C headers needed to compile the interface between the Java provider and the OpenSSL Library libraries.

#### 3.1 Clone repo
Clone this repository and change into the root directory of that clone.


```
git clone https://github.com/openssl-projects/openssl-jostle.git
cd openssl-jostle

ls -al

-rw-r--r--. 1 ec2-user ec2-user 11357 Oct  3 01:01 LICENSE
-rw-r--r--. 1 ec2-user ec2-user 14205 Oct  3 01:01 README.md
-rw-r--r--. 1 ec2-user ec2-user   800 Oct  3 01:01 build.gradle
-rw-r--r--. 1 ec2-user ec2-user   368 Oct  3 01:01 settings.gradle
-- etc

```

#### Set up Java 25

For this step you will need to have Java 25 on your PATH (aka command line), and you should also set 
```JAVA_HOME``` appropriately, for example:

```
#
# This value will be different depending on the machine you are building on
#
export JAVA_HOME=/usr/lib/jvm/java-25-amazon-corretto.x86_64

export PATH=$JAVA_HOME/bin:$PATH


java -version

openjdk version "25" 2025-09-16 LTS
OpenJDK Runtime Environment Corretto-25.0.0.36.2 (build 25+36-LTS)
OpenJDK 64-Bit Server VM Corretto-25.0.0.36.2 (build 25+36-LTS, mixed mode, sharing)

```
#### Build headers

Use gradlew to generate the headers, make sure you are in the root of the OpenSSL Jostle repository

```
./gradlew clean compileJava

.. some output..

BUILD SUCCESSFUL in 2s
2 actionable tasks: 2 executed
```

### Step 4. Compile interface

This step will compile and install the interface layer, both JNI and FFI that
connects the Java side of OpenSSL Jostle to the OpenSSL Library libraries.

#### CMAKE 
You will  need CMAKE version of at least 3.31

```
cmake -version

cmake version 3.31.6

CMake suite maintained and supported by Kitware (kitware.com/cmake).
```

#### Optional, build with Operations Test support

> __Skip this step if you do not want to perform Operations Testing!__

The interface libraries can be built with support for operations testing which should be left
out for normal use. 

If you want to do operations testing then set the following:

```
# This is optional, leave it unset 

export JOSTLE_OPS_TEST=true

# To unset

unset JOSTLE_OPS_TEST

```

#### Ensure OPENSSL_PREFIX is set

To build the interface you need to make sure the ```OPENSSL_PREFIX``` is set from either Step 2 or 
points to a directory that has the same structure as what the OpenSSL build would have generated.

You must also ensure that JAVA_HOME is set.

```
echo $OPENSSL_PREFIX 
/home/ec2-user/build/openssl_3_5

echo $JAVA_HOME
/usr/lib/jvm/java-25-amazon-corretto.x86_64/
```

#### Build and install the interface

To build:

```
    # The following should work for the bulk of users

    ./interface/build.sh

```

The build step will copy build products into the appropriate locations into 
``jostle/src/main/resources/native``

For example:

```
ls -alR jostle/src/main/resources/native/linux/
jostle/src/main/resources/native/linux/:
total 0
drwxr-xr-x. 4 ec2-user ec2-user 35 Oct  2 10:35 .
drwxr-xr-x. 4 ec2-user ec2-user 53 Oct  2 10:35 ..
drwxr-xr-x. 2 ec2-user ec2-user 22 Oct  2 10:35 aarch64
drwxr-xr-x. 2 ec2-user ec2-user 98 Oct  2 10:43 x86_64

jostle/src/main/resources/native/linux/aarch64:
total 4
drwxr-xr-x. 2 ec2-user ec2-user 22 Oct  2 10:35 .
drwxr-xr-x. 4 ec2-user ec2-user 35 Oct  2 10:35 ..
-rw-r--r--. 1 ec2-user ec2-user 69 Oct  2 10:33 deps.txt

jostle/src/main/resources/native/linux/x86_64:
total 7352
drwxr-xr-x. 2 ec2-user ec2-user      98 Oct  2 10:43 .
drwxr-xr-x. 4 ec2-user ec2-user      35 Oct  2 10:35 ..
-rw-r--r--. 1 ec2-user ec2-user      69 Oct  2 10:33 deps.txt
-rw-r--r--. 1 ec2-user ec2-user 7186360 Oct  2 08:08 libcrypto.so.3
-rwxr-xr-x. 1 ec2-user ec2-user   82680 Oct  2 10:43 libinterface_ffi.so
-rwxr-xr-x. 1 ec2-user ec2-user  102352 Oct  2 10:43 libinterface_jni.so

```

### Step 5. Building the Jar

To build the jar with the libraries baked in.
Note that the tests will be automatically run unless you use
provide "-x test" on the command line.

```
    # Ensure Java 25
    
    java -version
    
    openjdk version "25" 2025-09-16 LTS
    .. etc

    ./gradlew clean build
    
    # to skip testing
    
    ./gradlew clean build -x test
    
```

The Jostle jars can be found in:

```
    <repo>/jostle/build/libs/
```


### Step 6. Running DumpInfo

#### With modules

```
java --module-path jostle/build/libs/openssl-jostle-1.0-SNAPSHOT.jar \
--enable-native-access=org.openssl.jostle.prov \
--module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo
```

```
-------------------------------------------------------------------------------
DumpInfo

Provider:
  Info: Jostle Provider for OpenSSL v1.0.0-SNAPSHOT
  Name: JSL
  OS: Linux
  Version: 6.1.153-175.280.amzn2023.x86_64
  Arch: amd64
  Java Version: 25
  Java Vendor: Amazon.com Inc.

Loader:
  Load Attempted: true
  Load Successful: true
  Loader Message: Loader Finished Successfully
  Loader Interface Resolution Strategy: auto
  Loader Interface: FFI
  Loaded Native Libraries:
    Extracted: /native/linux/x86_64/libcrypto.so.3
    Extracted: /native/linux/x86_64/libinterface_ffi.so

Native Status:
  Native Available: true
  OpenSSL Version: 3.5.4
.END
Use: -fine to emit FINE level logs
-------------------------------------------------------------------------------
```


#### Without modules

```
-------------------------------------------------------------------------------
DumpInfo

Provider:
  Info: Jostle Provider for OpenSSL v1.0.0-SNAPSHOT
  Name: JSL
  OS: Linux
  Version: 6.1.153-175.280.amzn2023.x86_64
  Arch: amd64
  Java Version: 25
  Java Vendor: Amazon.com Inc.

Loader:
  Load Attempted: true
  Load Successful: true
  Loader Message: Loader Finished Successfully
  Loader Interface Resolution Strategy: auto
  Loader Interface: FFI
  Loaded Native Libraries:
    Extracted: /native/linux/x86_64/libcrypto.so.3
    Extracted: /native/linux/x86_64/libinterface_ffi.so

Native Status:
  Native Available: true
  OpenSSL Version: 3.5.4
.END
Use: -fine to emit FINE level logs
-------------------------------------------------------------------------------

```

NB: Java25 will emit a warning about access to restricted methods in java.lang.System.

```
WARNING: A restricted method in java.lang.System has been called
WARNING: java.lang.System::load has been called by org.openssl.jostle.Loader in an unnamed module (file:/home/ec2-user/build/jostle/jostle/build/libs/openssl-jostle-1.0-SNAPSHOT.jar)
WARNING: Use --enable-native-access=ALL-UNNAMED to avoid a warning for callers in this module
WARNING: Restricted methods will be blocked in a future release unless native access is enabled

```

#### Java 8

```
java -cp jostle/build/libs/openssl-jostle-1.0-SNAPSHOT.jar org.openssl.jostle.util.DumpInfo


-------------------------------------------------------------------------------
DumpInfo

Provider:
  Info: Jostle Provider for OpenSSL v1.0.0-SNAPSHOT
  Name: JSL
  OS: Linux
  Version: 6.1.153-175.280.amzn2023.x86_64
  Arch: amd64
  Java Version: 1.8.0_462
  Java Vendor: Amazon.com Inc.

Loader:
  Load Attempted: true
  Load Successful: true
  Loader Message: Loader Finished Successfully
  Loader Interface Resolution Strategy: auto
  Loader Interface: JNI
  Loaded Native Libraries:
    Extracted: /native/linux/x86_64/libcrypto.so.3
    Extracted: /native/linux/x86_64/libinterface_jni.so

Native Status:
  Native Available: true
  OpenSSL Version: 3.5.4
.END
Use: -fine to emit FINE level logs

```

#### java 25 -- default will use FFI

```
java --module-path jostle/build/libs/openssl-jostle-1.0-SNAPSHOT.jar \
--enable-native-access=org.openssl.jostle.prov \
--module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo

-------------------------------------------------------------------------------
DumpInfo

Provider:
Info: Jostle Provider for OpenSSL v1.0.0-SNAPSHOT

-- snipped

Loader:
Load Attempted: true
Load Successful: true
Loader Message: Loader Finished Successfully
Loader Interface Resolution Strategy: auto
Loader Interface: FFI  <-----
Loaded Native Libraries:
Extracted: /native/linux/x86_64/libcrypto.so.3
Extracted: /native/linux/x86_64/libinterface_ffi.so

-- snipped
```


#### Forcing use of JNI

Jostle will default to FFI when available, it can be forced to use JNI.

```
-Dorg.openssl.jostle.loader.interface=JNI
```

For example, with module loading

```
java -Dorg.openssl.jostle.loader.interface=JNI \
--module-path jostle/build/libs/openssl-jostle-1.0-SNAPSHOT.jar \
--enable-native-access=org.openssl.jostle.prov \
--module  org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo


-------------------------------------------------------------------------------
DumpInfo

Provider:
Info: Jostle Provider for OpenSSL v1.0.0-SNAPSHOT

-- snipped

Loader:
Load Attempted: true
Load Successful: true
Loader Message: Loader Finished Successfully
Loader Interface Resolution Strategy: jni
Loader Interface: JNI <----
Loaded Native Libraries:
Extracted: /native/linux/x86_64/libcrypto.so.3
Extracted: /native/linux/x86_64/libinterface_jni.so

-- snipped
```


#### Unsuccessful loading example

```
java -cp jostle/build/libs/openssl-jostle-1.0-SNAPSHOT.jar org.openssl.jostle.util.DumpInfo

java -cp openssl-jostle-1.0-SNAPSHOT.jar org.openssl.jostle.util.DumpInfo
Oct 02, 2025 10:02:41 PM org.openssl.jostle.Loader load
WARNING: extraction file '/native/osx/arm64/libcrypto.3.dylib' not found
java.io.IOException: extraction file '/native/osx/arm64/libcrypto.3.dylib' not found
	at org.openssl.jostle.Loader.extractAndLoad(Loader.java:389)
	at org.openssl.jostle.Loader.loadImpl(Loader.java:308)
	at org.openssl.jostle.Loader.load(Loader.java:104)
	at org.openssl.jostle.CryptoServicesRegistrar.<clinit>(CryptoServicesRegistrar.java:21)
	at org.openssl.jostle.jcajce.provider.JostleProvider.<init>(JostleProvider.java:54)
	at org.openssl.jostle.jcajce.provider.JostleProvider.<init>(JostleProvider.java:42)
	at org.openssl.jostle.util.DumpInfo.main(DumpInfo.java:41)

Exception in thread "main" java.lang.IllegalStateException: no access to native library
	at org.openssl.jostle.CryptoServicesRegistrar.assertNativeAvailable(CryptoServicesRegistrar.java:34)
	at org.openssl.jostle.jcajce.provider.JostleProvider.<init>(JostleProvider.java:54)
	at org.openssl.jostle.jcajce.provider.JostleProvider.<init>(JostleProvider.java:42)
	at org.openssl.jostle.util.DumpInfo.main(DumpInfo.java:41)

```

## Testing on multiple JVMs specifically

The build can execute tests on specific JVMs, the enable these tests users must set one or more
of the following environmental variables to the relevant JAVA_HOME for that JVM.

```
BC_JDK8= .. jdk8
BC_JDK17= .. jdk17
BC_JDK21= .. jdk21
BC_JDK25= .. jdk25

```

For example, setting:

```
export BC_JDK17=/usr/lib/jvm/java-17-amazon-corretto.x86_64
export BC_JDK8=/usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64
export BC_JDK21=/usr/lib/jvm/java-21-amazon-corretto.x86_64
export BC_JDK25=/usr/lib/jvm/java-25-amazon-corretto.x86_64
```

Will get picked up by the gradle build and will the trigger the addition of
extra JVM specific tests tasks to the main test task.

```
jostle: Adding test8 as dependency for test task because BC_JDK8 is defined
jostle: Adding test17 as dependency for test task because BC_JDK17 is defined
jostle: Adding test21 as dependency for test task because BC_JDK21 is defined
jostle: Adding test25 as dependency for test task because BC_JDK25 is defined
```

#### Notes

There is a unit test class dedicated to asserting the JVM version and which interface
library have been loaded. In normal testing they accept anything however for more
specific testing they will assert.

For example in ```integrationTest25JNI``` task.

```
jvmArgs = ['-Dtest.java.version.prefix=25', '-Dorg.bouncycastle.jostle.loader.interface=jni', '-Dtest.java.interface_type=jni']
```

These options are stipulating:
1. JVM version must start with '25' 
2. Loader must use the JNI interface
3. The test is expecting the 'jni' interface to be loaded.

See ```org.openssl.jostle.test.ExpectedJVMTest```

To build test:

```
./gradlew clean build
```

Note that it will take about four times longer to complete.


## Options

This section will cover property setting that effect usage and also includes a few common problems
that may arise for some usage scenarios.

### Available properties

Properties may be set in a security policy file or on the command line via -Dxxx

#### Property: "org.openssl.jostle.loader.install_dir"

Directly specify an installation directory rather than use one derived from the default temporary 
directory provided by the JVM. 

**This is very useful if your host system is configured to deny
execution from any binary file (this also includes libraries) that are installed in a temp drive.**

#### Property: "org.openssl.jostle.loader.single_install"

This property will cause the loader to use a fixed install location, if 
"org.openssl.jostle.loader.install_dir" is defined it will use that otherwise it will the default 
temp dir defined by the JVM.

This property is useful on systems with multiple instances running that would otherwise
create multiple copies of the same libraries.

It is advisable to use this with: "org.openssl.jostle.loader.install_dir"

#### Property: "org.openssl.jostle.loader.load_lib_NN"
This property allows you to override the list of native libraries loaded that are not interface libraries,
for example:

 ```
    org.openssl.jostle.loader.load_lib_00=/path/to/library
    org.openssl.jostle.loader.load_lib_01=/path/to/library1
    etc
    
 ```

The paths must be absolute paths and the loader will count from _00 to _99 it will
stop when it cannot find a property.

Please see:

https://docs.oracle.com/javase/8/docs/api/java/lang/System.html#load-java.lang.String-

#### Property: "org.openssl.jostle.loader.load_name_NN"

This property allows you to override the list of native libraries loaded that are not interface libraries,
example except it allows the specification of the library name rather than path. The JVM will use
whatever library lookup mechanism it has access to.

 ```
    org.openssl.jostle.loader.load_name_00=openssl
    org.openssl.jostle.loader.load_name_01=mymodule
    etc
   
 ```
The name must be compatible with ```System.loadLibrary(name);```. 
The loader will count from _00 to _99 and, it will stop when it cannot find a property.

Please review:

https://docs.oracle.com/javase/8/docs/api/java/lang/System.html#loadLibrary-java.lang.String-
https://docs.oracle.com/javase/8/docs/api/java/lang/System.html#mapLibraryName-java.lang.String-

#### Property: "org.openssl.jostle.loader.interface"

This property can be one of the following values:

|Setting| Description                                             |
|-------|---------------------------------------------------------|
| auto  | Loader will detect FFI / JNI interface automatically    |
| jni   | Force the extraction and use of the JNI interface only  |
| ffi   | Force the extraction and use of the FFI interface only  |
| none  | Do not extract an interface library                     |

If "none" is selected then the name or path to the interface library must
be defined by either:

1. org.openssl.jostle.loader.load_name_NN, or
2. org.openssl.jostle.loader.load_lib_NN

#### "org.openssl.jostle.ossl_prov"

Use this property to set the name of the OpenSSL provider module after loading.


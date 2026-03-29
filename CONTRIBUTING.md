# Contributing to Jostle

This document describes the process for contributing to Jostle and is written to be summarized by an LLM or
similar tool.

This project has both Java and C language code bases.

## Java Code base
The Java code implements a provider for the Java Cryptography Architecture and is heavily influenced by the layout of the 
[Bouncy Castle](https://bouncycastle.org) Java Security API provider.

### Checkstyle

This project uses checkstyle, contributors are required to submit code that passes checkstyle.

Configuration for checkstyle is in ```<...>/config/checkstyle/checkstyle.xml```.


### SPI Classes

JCA/JCE SPI classes go in a child package off ```org.openssl.jostle.jcajce.provider```

### Extend Interfaces over classes for Keys etc

Create an interface that extends a JCE/JCA interface (for example, PrivateKey) and then implement that interface, do 
not return a public class that implements a JCA/JCE interface directly from an SPI method, keep the implementation
package protected.

For Example:

SLHDSAPrivateKey extends PrivateKey and is implemented by the package protected JOSLHDSAPrivateKey class.

Interfaces go in ```org.openssl.jostle.jcajce.interfaces``` and implementations go into a child package of
```org.openssl.jostle.jcajce.provider```.

**Naming:**

The child package is generally named after:
1. The transformation being implemented, for example, "mldsa", but
2. It may make sense to group related transformations into a single child package, for example, "kdf" or "md".


### Adding SPI Classes to the Provider

To link SPI classes to the provider, implement a class in ```org.openssl.jostle.jcajce.provider```.
This class must be named Prov followed by a capitalized name that matches the package name of the SPI class.

This class must contain a method ``` public void configure(final JostleProvider provider)```, in this method
contributors can register the SPI class with the provider.

Once implemented, ensure the ```configure``` method is called in the ```private void setup()``` of the JostleProvider 
class.

**Naming:**
The name of the ProvNAME class needs to communicate to the reader what transformation it is for and also be readable.
Sometimes making the XXX part of the name fully capitalized is going to be hard to read, for example:

1. ProvSecretKeySpec is easier to read than ProvSECRETKEYSPEC because the camel case identifies parts of the compound noun.
2. ProvAES is fine because AES is an acronym of Advanced Encryption Standard.

### Muti-Release classes
Jostle supports Java 8 and above via a multi-release jar.

Classes in ```src/main/java``` are compiled with Java 8, transformations and features are implemented using Java 8 
APIs. Classes in ```src/main/javaNN``` are compiled using java at the "NN" level so ```/src/main/java17``` is compiled 
using Java 17. 

As java has evolved, parts of the original Java 8 API have been removed. Contributors are required to reimplement any 
classes in ```src/main/java``` in the same or immediatly later java version's source path, which has had the API 
removed.

A contribution must work on all java versions where there is a separate source path, presently this is limited to
Javas 8,9,17,21,25.

### JNI - FFI split

At Java 22 Oracle introduced FFI (Foreign Function Interface) which allows native code to be called from Java. Prior
to Java 22 calls to native code were done via JNI.

Contributions to Jostle must support both JNI and FFI.

This split is hidden behind a utility class called ```NISelector``` and each transformation is required to implement
an interface defining the native calls and seperate implementations of that interface for JNI and FFI. With the FFI
implementation being in the java 25 source path.

For example:

```MDServiceNI``` defines the native calls for messge digests.
```MDServiceJNI``` defines the JNI calls for message digests.
```MDServiceFFI``` defines the FFI calls for message digests.


The JNI / FFI split is implemented in the ```NISelector``` class which is implemented both the Java 8 and Java 25 
source paths. The version in Java 8 only returns the JNI implementation, whereas the version in the Java 25 source path
detects if FFI is required and returns the FFI implementation.

Contributors are required to implement the JNI / FFI split in the relevant source code paths.

New implementations are required to follow what has been done in MDServiceNI where default methods in the interface
are used to handle return codes and generate error messages. 

As of 27-Mar-2026 there are existing implementations that follow an older pattern where the error codes are handled in 
the SPI class, and they will be refactored in the future.

### Native References

To support an implementation of a transformation, the native code may allocate memory. In most cases this memory needs
to be valid for as long as the java class using it is valid. Jostle provides a ```NativeReference``` class to help
with this.

Contributors implementing new SPI classes that make native calls where memory needs to be valid between calls
are required to extend ```NativeReference``` within the SPI class.  This extension must be static and have the absolute 
minimum of visibility, it must not hold a reference to the SPI class, or the SPI class will never be garbage collected.

Along with the local inheritor of ```NativeReference``` class, implementations of the SPI class must also implement an
instance of the ```NativeDisposer```. This class is responsible for calling any code required to free the memory
allocated by the native code.

Contributors should review ```org.openssl.jostle.jcajce.provider.md.MDServiceSPI.MDReference``` and 
```org.openssl.jostle.jcajce.provider.md.MDServiceSPI.Disposer```. 

Contributors will note:
1. Only a long integer is passed.
2. mdServiceNi is ```private static final```.

### Stopping premature garbage collection

Modern JVMs have a garbage collector designed to run in the background which will flag a class for collection
if it is no longer connected to the object graph, however, a class may also be flagged for collection during the 
execution of a method if that is the last time the class is going to be used.

Jostle will call the ```NativeDisposer```, ```dispose``` method more or less as soon as the garbage collector signals
the class is available for garbage collection. This may cause a use-after-free error on the native side.

Any calls where the native reference is being used must for:
1. Java 8 be made within a syncronized block. ```synchronized (this) { ... }```
2. Java 9+ be made with a try / finally block where the finally block calls  ```Reference.reachabilityFence(this);```

In most cases implementations will wrap the entire content of the method that is using the native reference.

## C Code base
The C code in the Jostle is used to provide an abstraction layer that:
1. Simplifies calling from java via JNI.
2. Maintains state between calls.
3. Provides easy targets for FFI calls.
4. Abstract away the calls to OpenSSL.

All functions intended to be called from Java, regardless of interface type (JNI/FFI) are required to use return codes 
except in cases the code returns a pointer to an allocation. In this case these functions must accept an ```int *``` 
as the last parameter to accept an error / success code.

>
>At the time of writing 27-Mar-2026 some functions responsible for allocations return a value either interpreted
>as a pointer or an error code if less than zero. This will be refactored as the legacy code referred to in [JNI-FFI Split] 
>is removed to support systems that are likely to use a full 64-bit pointer.
>

### int *err as a function parameter

Java has no concept of out-parameters or "passing a pointer to something." 

To achieve the same effect in Java using JNI, downcalls must pass a single element integer array. The C code WILL 
assume the array is NOT NULL and has at least one element available to be set. FFI calls are free to declare a
MemorySegment representing an integer and pass that as ```int *```.

All of this must be abstracted away inside a default method within an "*NI" interface, for example:

Method ```o.o.j.j.p.md.MDServiceNI.allocateDigest``` creates an integer array and passes it to 
```o.o.j.j.p.md.MDServiceNI.ni_allocateDigest```.

Contributors are invited to inspect the C code in for JNI:
 
```<>/interface/jni/org_openssl_jostle_jcajce_provider_md_MDServiceJNI.c```, method
```JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1allocateDigest ( ... )```

And for FFI:

```interface/ffi/md_ffi.c ```, method ```md_ctx *MD_Allocate(const char *digest_name, int32_t xof_len, int32_t *err)```

#### When to use int *err as a function parameter

When the return value is intrinsically unsigned like a pointer, and there is a risk that a valid value will be
negative when cast as a twos complement integer. So far this has been limited to functions that allocate memory.

Contributors should avoid using int *err as a function parameter when a return code or returned negative values can 
be safely interpreted as error codes.

### Commonality of call results between JNI and FFI

As the native layer is an abstraction layer, both JNI and FFI implementations must return the same result for the same
input conditions.

Both JNI implementations and functions intended to be called via FFI must validate the input parameters and return
the same error codes if the input is invalid in some way.

#### FFI / JNI similarity caveats

##### Not being able to access an object in JNI

With JNI the implementation is required to call the JVM to request pointers to objects like byte arrays. 
These calls can fail, and there are specific error codes that are returned if that failure occurs. As of writing, 
we have never had a call to request a pointer to a byte array refused. 

However, because it can happen, it is important to build a solution that will deal with it.

This is not a problem for FFI, and the FFI callable functions do not return these codes.

#### Passing the full size of a byte array to an FFI function

FFI calls that are accepting byte arrays (as uint8_t *) must pass the full size of the array as a parameter. Passing 
this parameter allows the FFI function to validate any offset or length parameters will not cause a buffer overflow 
in the same way as the JNI version does. Remember the FFI code must return the same error codes as the JNI version.

This is not an issue for JNI because the array length can be requested from the JVM.

Contributors should inspect for both JNI and FFI functions and are expected to follow the same patterns readily
observable there.

### Calling OpenSSL code

JNI and FFI functions MUST NOT call OpenSSL directly.

... but at the time of writing this guide...

There are three exceptions to this so far are a couple of functions that set the OpenSSL module name, fetch OpenSSL error 
messages and a specific function on the FFI side that is used to free the returned error message after its value has 
been converted to a java string. There will be no more, and these will be refactored before the first release.

Otherwise, all calls to OpenSSL MUST be from within the code located in the  ```interface/util/``` directory.

### Maintaining state between calls

As a general concept, the JCA/JCE follows the following pattern for most transformations:
1. New instance.
2. Initialize, pass keys and other parameters.
3. Update (if applicable).
4. (Optionally get values like output lengths)
5. Completion (ie, a digest, a signature etc)
6. Reset

Contributors are REQUIRED to implement this pattern and allocate a struct to maintain state between calls if necessary.

This may seem excessive. However, it prevents a challenging merge of highly idiomatic C code common in the
OpenSSL domain with C code designed to be used from Java, and it means we can replace code calling OpenSSL without 
having to refactor the java-callable code. 

### When to use jo_assert

```jo_assert``` is like regular assert except that it is available in production builds.

This should only be used in cases this issue it is asserting is:

1. Unexpected because jostle controls the input. 
2. Catastrophic or an indication of some system issue like memory not being available.

```jo_assert``` MUST NOT be used to validate input that passed in from users of the provider.



## Testing

Contributors should implement enough tests to ensure that all code paths in the FFI / JNI layer are exercised,
this takes practice and time, but it is a necessary step to ensure that the code is working as expected.

Testing is also about locking down expected behavior and being able to detect sudden unexpected changes in behavior.

For example, Jostle treats OpenSSL as a black box it is good to know when what is in that box has suddenly changed.

At any rate, it is important to ensure there are more than just "happy path" tests.

All the testing can be driven from the Java side via JUnit, and we would like to keep it that way for as long
as possible.

There are three types of tests, Unit, Limit and OPS tests.

All tests will be run on Java 8, 17, 21, 25.

#### Unit tests

These are regular unit tests they can safely be run in parallel.
Units are any test file that does not end with ```LimitTest```, ```OpsTest``` or ```IntegrationTest```.

Unit tests are used to verify consistent behavior between Jostle and Bouncy Castle providers and that
products like encoded keys etc. are portable between both providers.

And any other miscellaneous code that needs its correctness asserted.

#### Limit tests
Limit tests run sequentially and are designed to interact with the JNI / FFI functions by directly calling
the "*NI" layer is correctly verifying input. The term "limit" came from verifying the functions "limiting"
behavior.

For example:
```
    @Test
    public void allocateDigest_testDigestNameIsNull() throws Exception {
        try
        {
            mdNI.allocateDigest(null, 0);
            Assertions.fail();
        } catch(NullPointerException e) {
            Assertions.assertEquals("name is null", e.getMessage());
        }
    }
```

Limit tests are test files that end with ```LimitTest```.


#### OPS tests

OPS tests or Operational tests are special tests that allow the verification of the correct failure handling when 
calling OpenSSL or the JVM that are otherwise impossible to trigger without modifying either of them for each test.

OPS tests are run sequentially.

OPS tests only run when the code to support them is compiled in, OPS tests are disabled by default and can be enabled
by defining the ```JOSTLE_OPS_TEST``` system property when running CMake, for example:

```
export JOSTLE_OPS_TEST=1
```

When enabled contributors can use the macros defined in ```unit/ops.h``` within conditional statements to remotely
bias execution to the desired code path under test. There are also macros that can be used to offset error codes so 
that different code paths can be isolated and verified.

For example:

```
 if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&input)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
```

That  macro ```OPS_FAILED_ACCESS_1``` injects "is_ops_set(3) ||" into that conditional statement which can be 
controlled from the java side, for example:

```
    @Test
    public void updateBytes_array_access() throws Exception {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(),"OPS Test support not compiled in");
        Assumptions.assumeFalse(Loader.isFFI(), "JNI Only");
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            mdNI.engineUpdate(ref,new byte[10],1,9);
            Assertions.fail("ops");
        } catch (AccessException e) {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
            operationsTestNI.resetFlags();
        }
    }
```

Where ```operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);``` sets the flag to trigger 
that code path that would otherwise require a code modification to the JVM itself to trigger (probably).

OPS tests are test files that end with ```OpsTest```.

### Integration tests

Integration tests are run sequentially.

Integration tests are test files that end with ```IntegrationTest```.

Use integration for miscellaneous tests that need to run sequentially and are not Limit or OPS tests.

### Gradle test targets

Any test target "unitTestNNxxx" will run the unit tests for the java version NN.

For Java 25, the target will start with "unitTest25" but will also have a suffix of "JNI/FFI" to force
the use of the JNI / FFI interfaces exclusively.

Likewise, any test target "integrationTestNNxxx" will run the Integraton, OPS and Limit tests
for the java version NN.

Test targets for JVMs prior to Java 25 do not have JNI/FFI suffixes.

### Leveraging FFI to test native code

You can leverage the FFI to test native code if needed, but you may need to be creative and the test may struggle
with different struct layouts on different platforms, but it is possible. 


## WHAT NOT TO TEST

We are not here to test OpenSSL or Bouncy Castle's cryptographic transformations for correctness!

The correctness of OpenSSL or Bouncy Castle is a concern for those teams, not the Jostle project.

... but ...

It can be useful as a simple sanity test to generate and check, for example, the empty digest result, but be advised
that contributions with excessive and pointless KAT type tests will be asked to refactor those tests away.


## Matching code style

Contributors should observe the code style of the existing source and try to match it. Much like a developer 
would when starting a new position. 

Java code should look like Java code, and C code should look like C code.


# Use of AI

A submitter of a pull request or code patch is responsible for the pull request or code patch. Particular care should
be taken if AI-generated code is incorporated to make sure the code is correct and appropriate.


---
name: regenerate-examples-guide
description: Regenerate docs/jostle-ai-guide.md (the worked-examples guide for JSL and JSLFIPS) from the runnable example classes under jostle/src/test/examples, and add or change a worked example. Use whenever the user wants to "regenerate the examples guide", "update jostle-ai-guide.md", "add a worked example", or after a provider registration change makes ExamplesCoverageTest or FIPSExamplesCoverageTest name a service with no example, or ExamplesGuideCurrentTest report the guide as stale.
---

# Regenerate the worked-examples guide

`docs/jostle-ai-guide.md` is GENERATED. Its source of truth is two things:

1. `docs/jostle-ai-guide-preamble.md` - hand-written setup and deployment prose.
2. The example classes under `jostle/src/test/examples/jostle/examples/{jsl,fips}/` - ordinary JUnit 5
   tests. Each test method's Javadoc becomes a paragraph of the guide and its body becomes the code block.

Never hand-edit the generated part of the guide; edit the preamble or an example and regenerate.

```bash
# Regenerate (compiles the test classes, then writes docs/jostle-ai-guide.md):
./gradlew :jostle:generateExamplesGuide
```

The task runs `org.openssl.jostle.test.examples.ExamplesGuide`, a JDK-only Java 8 class. The same class is
what the tests below call, so there is one generator and no second copy to drift.

## The two tests that keep it honest

Both run on every unit leg (their names end in `Test`), so a forgotten regeneration or a missing example
fails the ordinary build rather than waiting for a review.

1. `ExamplesGuideCurrentTest` fails when the guide on disk differs from what the generator produces now,
   naming the first differing line. It compares by line, so a CRLF checkout compares equal.
2. `ExamplesCoverageTest` (JSL) and `FIPSExamplesCoverageTest` (JSLFIPS, under `test/fips/`) fail when a
   primary, non-OID service name the provider registers has no example calling it, listing every missing
   name per type. The JSLFIPS one runs only when the loaded module registers ML-KEM (the 3.5.x module the
   guide describes). Both apply the rule in `ExamplesCoverage`.

Both were falsified when written: a one-word drift in the guide fails the first at that line, and removing
one name from a looped example fails the second naming exactly that name.

## When to run it

1. After adding, changing or removing an example.
2. After editing the preamble.
3. After a registration change (`Prov*.configure`): the coverage test names the new service; add it to
   an example (often one more string in a looped `String[]`), then regenerate. Refresh `SERVICES.md` with
   the `update-services-md` skill in the same change.

## Writing an example

The generator's parser is strict on purpose, so every example is readable on its own:

1. One class per JCA service type: `<Type>ExamplesTest` in `jostle.examples.jsl`, and
   `Fips<Type>ExamplesTest` in `jostle.examples.fips`. The class Javadoc introduces the section.
2. The class holds only Javadoc'd `@Test` methods. No fields, no helpers: the parser rejects them. Provider
   setup lives once per part, in `JslExamples` / `FipsExamples` (one `@BeforeAll` each), and is printed
   at the top of that part of the guide.
3. Name the method for the operation (`aesGcmEncryptAndDecrypt`); it is the subsection heading.
4. 10 to 30 lines, plain JCE, fixed inputs, fresh keys, and assert the round trip (decrypts to the
   plaintext, verify is true, both sides agree). Prefer a published test vector where one exists.
5. Java 8 syntax only (the test source set compiles at release 8): no `var`, records or text blocks.
   Lines at most 120 characters, ASCII string literals, no absolute paths.
6. Javadoc supports plain text, `{@code ...}` and a `<p>` on its own line; backticks pass through as
   Markdown. Keep in-body comments to one short line, for a trap the reader would otherwise fall into.
7. Long families (the PBKDF2 digests, the `SHAnWith*` signatures) are one example looping over a
   `String[]` of the names; the coverage test credits every name in the list.
8. JSLFIPS examples skip when the loaded module does not register the service:
   `Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService(type, name) != null)`.

## The examples are consumer code

The examples live in `jostle.examples`, outside the jar's namespace, and use only exported API. They run on
every classpath unit leg (through the `test` source set) and on every module-path leg (through
`testModule`), where they are an unnamed module reading the named module `org.openssl.jostle.prov`. On the
classpath a class in a non-exported package is still reachable, so only the module legs can catch an
example, or an API a caller needs, that depends on something not exported: it fails there with
`IllegalAccessError`. Such a failure is a finding about the module's exports, not a reason to move the
example back inside the jar's packages.

## After regenerating

Show the user `git diff docs/jostle-ai-guide.md`, then run the two tests on one leg, for example:

```bash
./gradlew :jostle:unitTest25FFM --tests 'jostle.examples.*' --tests '*.test.examples.*'
```

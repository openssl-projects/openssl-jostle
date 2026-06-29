---
name: update-services-md
description: Regenerate SERVICES.md (a markdown inventory of every algorithm the Jostle provider registers, grouped by JCA service type — KeyFactory, Cipher, Signature, KeyStore, Mac, MessageDigest, …) by running the DumpInfo diagnostic with its --services flag and parsing the output. Use this skill whenever the user wants to refresh or produce the provider's service list — including phrases like "update SERVICES.md", "regenerate the services list", "list provider services", "dump the services", "what algorithms does the provider register", "refresh the services inventory". Also useful after adding, removing, or renaming a service registration in a Prov<NAME>.configure(...) class, or after pulling changes that may have altered the registered algorithm set.
---

# Regenerate SERVICES.md from DumpInfo --services

`org.openssl.jostle.util.DumpInfo` is the provider diagnostic entry point. With
the `--services` argument it prints every service the `JSL` provider registers,
grouped by JCA service type, in the form:

```
Services (293 total, grouped by type):
  Cipher (41):
    AES
    AES/CCM/NOPADDING
    ...
  KeyFactory (31):
    EC
    Ed25519
    ...
```

This skill runs that, parses the `Services (...)` section, and writes a markdown
inventory to **`SERVICES.md` at the repo root** (beside `README.md`). The
registered set is fixed by the provider's `Prov<NAME>.configure(...)` code, not
by the DumpInfo flag, so the output is deterministic for a given build.

## When to use this skill

Trigger phrases (any of):

1. "update SERVICES.md" / "regenerate the services list" / "refresh the services inventory"
2. "list / dump the provider services" / "what algorithms does the provider register"
3. After editing a `Prov<NAME>.configure(JostleProvider)` registration (added / removed / renamed an algorithm).
4. After a merge or pull that may have changed the registered algorithm set.

## Prerequisite: a built jar

The skill runs DumpInfo against the assembled multi-release jar, so it must
exist and reflect current sources:

```bash
# Build (or rebuild) the jar from current sources. The jar bundles the native
# libraries, so DumpInfo self-extracts them at runtime.
./gradlew :jostle:jar
```

If provider registrations changed, rebuild first or SERVICES.md will reflect the
stale jar. The script errors clearly if no jar is present, and also if the jar
predates the `--services` flag (the section will be empty).

## How to run

The script is at `scripts/update_services_md.py`. From the repo root:

```bash
# Run DumpInfo --services and (over)write SERVICES.md at the repo root.
python3 .claude/skills/update-services-md/scripts/update_services_md.py
```

It uses `$JAVA_HOME/bin/java` if `JAVA_HOME` is set, otherwise `java` on `PATH`
(any JDK 8–25 works — the jar is multi-release). On success it prints, e.g.:

```
wrote /…/SERVICES.md: 293 services across 14 types
```

For an offline / test path — parse a captured DumpInfo dump instead of launching
java:

```bash
java -cp jostle/build/libs/openssl-jostle-*.jar org.openssl.jostle.util.DumpInfo --services > /tmp/dump.txt
python3 .claude/skills/update-services-md/scripts/update_services_md.py --input /tmp/dump.txt
```

## Output format

`SERVICES.md` opens with a "generated — do not edit by hand" banner and the
total service / type counts, then a `## <Type> (count)` section per JCA service
type (alphabetical, as DumpInfo emits them), each listing the registered
algorithm names and OID aliases as a numbered list in backticks. The whole file
is regenerated on every run, so re-running after a registration change produces a
clean diff of exactly what was added or removed.

## After regenerating

Show the user the counts and the diff (`git diff SERVICES.md`) so they can see
which algorithms changed, then let them commit. The file is a generated
artifact; do not hand-edit it — change the provider registration and re-run.

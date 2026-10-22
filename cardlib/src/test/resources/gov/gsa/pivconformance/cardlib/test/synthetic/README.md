# Synthetic CCT software test inputs

`SyntheticFixtures` generates these eight files from Cardlib's test source.
They contain invented identifiers, labeled test text and a newly generated public
test certificate. No input is read from a card or imported from a card corpus.
The signing key exists only during generation and is never written to disk.
These files are test resources, excluded from the application JAR/runnable ZIP.

`chuid.bin` has a detached, verifiable CMS signature over its synthetic fields.
`face-header.bin` and `fingerprint-header.bin` contain CBEFF/record headers and
CMS framing **without portrait/JPEG data, fingerprint images or minutiae**.
They test decoding and selected header fields, not complete biometric formats
or image quality. `security.bin` uses a labeled CMS payload to test parsing;
it does not test a complete LDS hash table.
The same certificate is reused for two certificate-container parser cases.

Conformancelib reuses these inputs in tests selected by the existing databases.
Its cryptographic tests also generate signed certificates and CHUIDs.
Neither suite replaces physical-card acceptance.

To regenerate, use Java 17 from `cardlib`:

```sh
./gradlew regenerateSyntheticFixtures
./gradlew check
```

Regeneration uses a fresh RSA-2048 key, so public certificate/signature bytes
change. Review regenerated files together and rerun Conformancelib's `check`.

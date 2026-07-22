# Reproducible CrackMe Fixture

`complex_crackme.c` is a benign, source-controlled Linux ELF fixture for opt-in
reverse-engineering acceptance tests. It uses a 24-byte token, staged indirect
validation, permuted byte constraints, a rolling state machine, decoy logic,
and encoded user-facing strings.

Build the analysis sample without embedding the source in the analyzer image:

```sh
mkdir -p /tmp/rikune-crackme-build
gcc -std=c11 -O2 -fPIE -pie -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 -fcf-protection=full -fno-ident \
  -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
  -o /tmp/rikune-crackme-build/complex_crackme complex_crackme.c
strip --strip-all /tmp/rikune-crackme-build/complex_crackme
```

The default test suite never executes the fixture. Any oracle check must run in
an isolated, no-network container with a read-only filesystem. Ground truth is
kept out of the uploaded sample and should only be used after static analysis
to score the result.

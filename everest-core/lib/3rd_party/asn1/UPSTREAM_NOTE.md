<!-- Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED -->

# ASN.1 sources — upstream provenance & normalization

These schemas come from ISO/PAS 15118-202:2025 (ed-1), fetched from the
official ISO server by `fetch_asn1.sh`:

- `esdp_extensions.asn`  <- https://standards.iso.org/iso/pas/15118/-202/ed-1/en/ESDPExtensions.asn
- `enp_extensions.asn`   <- https://standards.iso.org/iso/pas/15118/-202/ed-1/en/ENPExtensions.asn

## Why the files are normalized (do not skip)

The **official ISO-hosted `.asn` files contain a transcription defect**: the
information-object field references are split across lines, e.g.

    extensionID   EXTENSION.
                           &id ({ExtensionSet}),

This is invalid ASN.1 — `EXTENSION.&id` is a single token and must not be
broken by a newline. As published, the files fail to parse in every ASN.1
compiler tested (asn1c, asn1tools, pycrate). This is an upstream issue, not
a local one; anyone downloading the files from ISO hits the same failure.

## What the build does about it

`fetch_asn1.sh`:
1. Downloads each file and saves the untouched original as `*.asn.orig`
   (provenance — this is exactly what ISO ships).
2. Applies a narrow, auditable normalization that rejoins only the
   `.<newline>&` breaks:  `perl -0777 -pi -e 's/\.\s*\n\s*&/.&/g'`
   Nothing else in the schema is modified.
3. Verifies no broken references remain and the joined tokens are present.

The normalized files are what the rest of the build (asn1c bridge, pycrate
oracle, or hand-written codec) consumes. **Do not hand-edit the `.asn`
files** — re-run `fetch_asn1.sh` so the repair stays reproducible and the
deviation from the verbatim ISO download stays documented.

Diff `*.asn` against `*.asn.orig` to see exactly what was changed.

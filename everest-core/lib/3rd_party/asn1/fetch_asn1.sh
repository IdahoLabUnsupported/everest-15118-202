#!/usr/bin/env bash
# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
#
# Fetch + normalize the ISO/PAS 15118-202 ASN.1 schemas.
#
# WHY THIS EXISTS
# ---------------
# The official ISO-hosted schema files ship with a transcription defect: the
# information-object field references in ESDPExtension / ENPExtension are split
# across lines, e.g.
#
#     extensionID   EXTENSION.
#                            &id ({ExtensionSet}),
#
# This is malformed ASN.1 — the token "EXTENSION.&id" must not be broken by a
# newline. EVERY ASN.1 compiler (asn1c, pycrate, asn1tools, ...) rejects it as
# published. We therefore fetch the upstream file, keep an untouched *.orig for
# provenance, and apply a narrow normalization that rejoins ONLY the
# ".<newline>&" breaks. Nothing else in the schema is altered.
#
# This runs at build time so regeneration is reproducible and the deviation
# from the verbatim ISO download is explicit and auditable — no hand-edited
# copy that can silently drift.
#
# Upstream URLs (ISO/PAS 15118-202:2025, ed-1):
#   https://standards.iso.org/iso/pas/15118/-202/ed-1/en/ESDPExtensions.asn
#   https://standards.iso.org/iso/pas/15118/-202/ed-1/en/ENPExtensions.asn
#
# Usage:
#   ./fetch_asn1.sh            # fetch + normalize into the default dir
#   ./fetch_asn1.sh --host     # run directly on host instead of in a container
#   ASN1_DIR=some/path ./fetch_asn1.sh
#   ASN1_OUTPUT_UID="$(id -u)" ASN1_OUTPUT_GID="$(id -g)" ./fetch_asn1.sh
#
set -euo pipefail

# ---- configuration ---------------------------------------------------------
ASN1_DIR="${ASN1_DIR:-lib/3rd_party/asn1}"
ASN1_OUTPUT_UID="${ASN1_OUTPUT_UID:-0}"
ASN1_OUTPUT_GID="${ASN1_OUTPUT_GID:-0}"
ESDP_URL="https://standards.iso.org/iso/pas/15118/-202/ed-1/en/ESDPExtensions.asn"
ENP_URL="https://standards.iso.org/iso/pas/15118/-202/ed-1/en/ENPExtensions.asn"

# Map upstream URL -> local filename used by the rest of the build.
ESDP_LOCAL="esdp_extensions.asn"
ENP_LOCAL="enp_extensions.asn"

# ---- core logic (runs either on host or inside the container) ---------------
# Written as a function so the same code path is used in both modes.
normalize_one() {
    # $1 = url, $2 = destination path (final, normalized), $3 = human label
    url="$1"; dest="$2"; label="$3"
    orig="${dest}.orig"

    echo ">> ${label}"
    echo "   fetching: ${url}"
    # -f: fail on HTTP errors; -S: show errors; -L: follow redirects.
    curl -fSL --retry 3 --retry-delay 2 -o "${orig}" "${url}"

    # Sanity: non-empty and looks like ASN.1.
    if [ ! -s "${orig}" ]; then
        echo "   ERROR: downloaded file is empty" >&2
        return 1
    fi
    if ! grep -q "DEFINITIONS" "${orig}"; then
        echo "   ERROR: downloaded file does not look like an ASN.1 module" >&2
        return 1
    fi

    # Count broken field references before repair (for the log + note).
    breaks_before="$(grep -cE "EXTENSION\.\s*$" "${orig}" || true)"
    echo "   upstream .orig saved: ${orig}"
    echo "   broken field-ref line breaks detected: ${breaks_before}"

    # Apply the NARROW normalization onto a working copy:
    #   \.\s*\n\s*&   ->   .&
    # -0777 slurps the whole file so the regex can span the newline. The pattern
    # only matches a dot immediately (modulo whitespace) followed by '&', which
    # is unique to these IOC field references; it will NOT touch '...' markers,
    # comment periods, or anything else.
    cp -f "${orig}" "${dest}"
    perl -0777 -pi -e 's/\.\s*\n\s*&/.&/g' "${dest}"

    # Verify the repair: there must be no dangling "EXTENSION." at end of line,
    # and the joined tokens must now be present.
    breaks_after="$(grep -cE "EXTENSION\.\s*$" "${dest}" || true)"
    if [ "${breaks_after}" != "0" ]; then
        echo "   ERROR: ${breaks_after} broken reference(s) remain after normalization" >&2
        echo "          upstream format may have changed — inspect ${dest}" >&2
        return 1
    fi
    if ! grep -qE "EXTENSION\.&(id|Type)" "${dest}"; then
        echo "   ERROR: expected joined tokens (EXTENSION.&id / .&Type) not found" >&2
        echo "          upstream format may have changed — inspect ${dest}" >&2
        return 1
    fi

    echo "   normalized file written: ${dest}  (repaired ${breaks_before} break(s))"
    echo
}

write_note() {
    note="$1/UPSTREAM_NOTE.md"
    cat > "${note}" <<'NOTE'
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
NOTE
    echo ">> provenance note written: ${note}"
}

run_all() {
    mkdir -p "${ASN1_DIR}"
    normalize_one "${ESDP_URL}" "${ASN1_DIR}/${ESDP_LOCAL}" "ESDP extensions"
    # ENP is the second module in the standard (clause 7.5). Comment out if you
    # only need ESDP right now.
    normalize_one "${ENP_URL}"  "${ASN1_DIR}/${ENP_LOCAL}"  "ENP extensions"
    write_note "${ASN1_DIR}"
    echo ">> DONE. Normalized ASN.1 in ${ASN1_DIR}"
    echo "   (originals preserved as *.asn.orig; see UPSTREAM_NOTE.md)"
}

# ---- entry point: host mode or container mode ------------------------------
if [ "${1:-}" = "--host" ]; then
    # Run directly on the host. Requires curl + perl available locally.
    run_all
else
    # Guard: must run from the repo root, NOT from inside the asn1 dir, or we
    # create a nested lib/3rd_party/asn1/lib/... tree.
    case "$PWD" in
        */lib/3rd_party/asn1|*/lib/3rd_party/asn1/*)
            echo "ERROR: run this from the repo root, not from inside ${ASN1_DIR}." >&2
            echo "       cd to the directory that CONTAINS '${ASN1_DIR}' and retry." >&2
            exit 1;;
    esac
    if [ ! -d "$(dirname "${ASN1_DIR}")" ] && [ "${ASN1_DIR}" != "." ]; then
        echo "ERROR: parent of ASN1_DIR (${ASN1_DIR}) does not exist under $PWD." >&2
        echo "       Are you in the repo root?" >&2
        exit 1
    fi

    # Container mode: real Docker. Runs as root for apt, but a trap normalizes
    # output ownership even if an earlier step fails under set -e.
    docker run --rm \
        -e ASN1_OUTPUT_UID="${ASN1_OUTPUT_UID}" \
        -e ASN1_OUTPUT_GID="${ASN1_OUTPUT_GID}" \
        -e ASN1_DIR="${ASN1_DIR}" \
        -e ESDP_URL="${ESDP_URL}" -e ENP_URL="${ENP_URL}" \
        -e ESDP_LOCAL="${ESDP_LOCAL}" -e ENP_LOCAL="${ENP_LOCAL}" \
        -v "$PWD":/work \
        ubuntu:24.04 bash -c '
            set -eu
            export DEBIAN_FRONTEND=noninteractive

            # Normalize ownership on ANY exit (success or failure), so a
            # partial fetch cannot leave bind-mounted outputs inconsistent.
            trap "chown -R \"$ASN1_OUTPUT_UID:$ASN1_OUTPUT_GID\" \"/work/${ASN1_DIR}\" 2>/dev/null || true" EXIT

            apt-get update -qq
            apt-get install -y -qq --no-install-recommends \
                curl ca-certificates perl grep
            cd /work

            '"$(declare -f normalize_one write_note run_all)"'

            run_all
        '
fi

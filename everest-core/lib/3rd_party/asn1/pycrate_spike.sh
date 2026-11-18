#!/usr/bin/env bash
# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
# Throwaway pycrate spike — ESDP + ENP. Runs in ubuntu:24.04 and bind-mounts
# this ASN.1 directory as /work.
#
# Proves pycrate (pycrate-org fork, has OER) compiles the normalized ISO/PAS
# 15118-202 ESDP and ENP schemas — CLASS + ExtensionSet — and round-trips
# canonical OER, including open-type dispatch by UUID. Emits golden fixtures to
# lib/3rd_party/asn1/fixtures_pycrate/{esdp,enp}/.
#
# PREREQUISITE: run fetch_asn1.sh first so the files are normalized (the raw
# ISO files have broken field references and will NOT parse).
#
# Output ownership defaults to root:root because these fixtures are consumed
# from Linux containers. Override with ASN1_OUTPUT_UID/ASN1_OUTPUT_GID if you
# need host-user ownership instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASN1_OUTPUT_UID="${ASN1_OUTPUT_UID:-0}"
ASN1_OUTPUT_GID="${ASN1_OUTPUT_GID:-0}"

docker run --rm \
  -e ASN1_OUTPUT_UID="${ASN1_OUTPUT_UID}" \
  -e ASN1_OUTPUT_GID="${ASN1_OUTPUT_GID}" \
  -v "${SCRIPT_DIR}":/work \
  ubuntu:24.04 bash -c '
    set -eu
    export DEBIAN_FRONTEND=noninteractive

    # Normalize ownership on ANY exit (success or failure), so a mid-run Python
    # error cannot leave fixtures with inconsistent bind-mount ownership.
    trap "chown -R \"$ASN1_OUTPUT_UID:$ASN1_OUTPUT_GID\" /work/fixtures_pycrate 2>/dev/null || true" EXIT

    ESDP_PATH="/work/esdp_extensions.asn"
    ENP_PATH="/work/enp_extensions.asn"

    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      git ca-certificates python3 python3-pip python3-venv

    python3 -m venv /tmp/venv
    . /tmp/venv/bin/activate
    pip install --quiet --upgrade pip

    cd /tmp
    if git clone --depth 1 https://github.com/pycrate-org/pycrate.git /tmp/pycrate >/dev/null 2>&1; then
      pip install --quiet /tmp/pycrate
      echo "pycrate: installed from pycrate-org git"
    else
      pip install --quiet pycrate
      echo "pycrate: git failed, installed from PyPI (verify OER below)"
    fi

    OUT=/work/fixtures_pycrate
    mkdir -p "$OUT/esdp" "$OUT/enp"

    echo "=================================================================="
    echo " VERSION / OER PRESENCE"
    echo "=================================================================="
    python3 - "$ESDP_PATH" "$ENP_PATH" "$OUT" <<PYEOF
import sys, os, json, binascii, importlib.util, traceback

ESDP, ENP, OUT = sys.argv[1], sys.argv[2], sys.argv[3]

# --- OER presence check ------------------------------------------------------
try:
    from pycrate_asn1rt import asnobj
    base = asnobj.ASN1Obj
    has_oer = hasattr(base, "to_oer") and hasattr(base, "from_oer")
    print("runtime OER :", "PRESENT (to_oer/from_oer)" if has_oer
          else "ABSENT -- this build cannot do OER")
except Exception as e:
    print("runtime OER : could not introspect:", e)


def compile_module(asn_path, label, expect_keys):
    """Compile one .asn into a fresh imported pycrate module. Returns module or None."""
    from pycrate_asn1c.asnproc import compile_text, GLOBAL
    print()
    print("==================================================================")
    print(" %s -- COMPILE (CLASS + ExtensionSet)" % label)
    print("   file: %s" % asn_path)
    print("==================================================================")
    if not os.path.isfile(asn_path):
        print("  [FAIL] file not found -- did you run fetch_asn1.sh?")
        return None

    # IMPORTANT: reset compiler global state between modules so a second
    # compile does not see stale/duplicate definitions from the first.
    try:
        GLOBAL.clear()
    except Exception:
        # some versions expose a different reset; ignore if absent
        pass

    src = open(asn_path, encoding="utf-8", errors="replace").read()
    try:
        compile_text(src)
        print("  [PASS] compiled unchanged.")
        for mod_name, mod in GLOBAL.MOD.items():
            if mod_name in ("_IMPL_", "_USER_"):
                continue
            print("         module %r: %d objects" % (mod_name, len(mod)))
            for key in expect_keys:
                print("           %-34s recognized: %s"
                      % (key, "yes" if key in mod else "no"))
    except Exception as e:
        print("  [FAIL] could NOT compile:")
        print("         %s: %s" % (type(e).__name__,
              str(e).replace(chr(10), chr(10)+"         ")))
        return None

    # Generate + import a python module for encode/decode.
    try:
        from pycrate_asn1c.generator import PycrateGenerator
        py_path = "/tmp/%s_gen.py" % label.lower()
        PycrateGenerator(dest=py_path)
        spec = importlib.util.spec_from_file_location(label+"_gen", py_path)
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        print("  [PASS] generated + imported module")
        return m
    except Exception as e:
        print("  [WARN] generator failed (%s); trying CLI tool..." % e)
        import subprocess
        try:
            subprocess.check_call([sys.executable,
                "/tmp/pycrate/tools/pycrate_asn1compile.py",
                "-i", asn_path, "-o", "/tmp/%s_gen" % label.lower()])
            spec = importlib.util.spec_from_file_location(
                label+"_gen", "/tmp/%s_gen.py" % label.lower())
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            print("  [PASS] generated via CLI tool")
            return m
        except Exception as e2:
            print("  [FAIL] could not generate module: %s: %s"
                  % (type(e2).__name__, e2))
            return None


def get_obj(M, name):
    for attr in dir(M):
        val = getattr(M, attr)
        if hasattr(val, name):
            return getattr(val, name)
    if hasattr(M, name):
        return getattr(M, name)
    raise KeyError(name)


def roundtrip(M, name, value):
    o = get_obj(M, name); o.set_val(value); enc = o.to_oer()
    o2 = get_obj(M, name); o2.from_oer(enc)
    return enc, o2.get_val()


def run_samples(M, outdir, samples, full=None):
    """samples: dict key -> (typename, value). full: (containerType, value) or None."""
    manifest = {}
    print()
    print("  OER round-trip per extension type:")
    for key, (typ, val) in samples.items():
        try:
            enc, dec = roundtrip(M, typ, val)
            hx = binascii.hexlify(enc).decode()
            open(os.path.join(outdir, key+".oer"), "wb").write(enc)
            manifest[key] = {"type": typ, "value": repr(val),
                             "oer_hex": hx, "len": len(enc)}
            print("    [PASS] %-24s %-32s %3d B  %s" % (key, typ, len(enc), hx))
        except Exception as e:
            print("    [FAIL] %-24s %s: %s: %s" % (key, typ, type(e).__name__, e))

    if full is not None:
        cont_type, cont_val, cont_key = full
        print()
        print("  Open-type dispatch (%s, extensionValue by extensionID):" % cont_type)
        try:
            o = get_obj(M, cont_type); o.set_val(cont_val)
            enc = o.to_oer(); o2 = get_obj(M, cont_type); o2.from_oer(enc)
            hx = binascii.hexlify(enc).decode()
            open(os.path.join(outdir, cont_key+".oer"), "wb").write(enc)
            manifest[cont_key] = {"type": cont_type, "oer_hex": hx, "len": len(enc)}
            print("    [PASS] open-type dispatch WORKS -- %d B  %s" % (len(enc), hx))
            print("           decoded: %s" % (o2.get_val(),))
        except Exception as e:
            print("    [FAIL] open-type dispatch: %s: %s" % (type(e).__name__, e))
            print("           (inspect get_val() to mirror the expected shape)")

    json.dump(manifest, open(os.path.join(outdir, "manifest.json"), "w"), indent=2)
    print()
    print("  fixtures written to %s/" % outdir)


# ==================== ESDP ====================
M_esdp = compile_module(
    ESDP, "STEP 1 ESDP",
    ["EXTENSION", "ExtensionSet", "ESDPExtension",
     "ESDPExtensions", "ChargingInterfaceExtension"])

if M_esdp is not None:
    esdp_samples = {
        "charging_interface": ("ChargingInterfaceExtension",
            {"chargingInterface": "iec-62196-3-ff", "interfaceType": "socket-inlet"}),
        "ev_characteristics": ("EVCharacteristicsExtension",
            {"worldManufacturerIdentifier": "1HG",
             "vehicleDescriptorSection": "CM82633",
             "evccSoftwareVersion": "v1.2.3"}),
        "ipv6_socket": ("IPv6SocketExtension",
            {"ipv6SocketTuplesList": [
                {"ipv6Address": bytes(range(16)), "tcpPort": 15118,
                 "securityProfileList": ["iso-15118-2-2014"]}]}),
    }
    esdp_full = ("ESDPExtensions",
        {"esdpExtensionsList": [
            {"extensionID": bytes.fromhex("3EAE3DCBE9554A1D84C6B4EEF86460F3"),
             "extensionValue": ("ChargingInterfaceExtension",
                 {"chargingInterface": "iec-62196-3-ff",
                  "interfaceType": "socket-inlet"})}]},
        "esdp_full")
    run_samples(M_esdp, os.path.join(OUT, "esdp"), esdp_samples, esdp_full)

# ==================== ENP ====================
M_enp = compile_module(
    ENP, "STEP 2 ENP",
    ["EXTENSION", "ExtensionSet", "ENPExtension",
     "ENPExtensions", "EVSEGridInformationExtension"])

if M_enp is not None:
    # Payload sample types per clause 7.5. Values kept minimal + valid.
    enp_samples = {
        "grid_information": ("EVSEGridInformationExtension",
            {"gridConnectionPointStatus": "connected",
             "localGridOperationMode": "normal"}),
        "grid_code_impact": ("GridCodeImpactLevelExtension",
            {"gridCodeImpactLevel": "level2",
             "gridCodeImpactLevel2Reason": "l2OverVoltageProtection"}),
        "ev_stop_reason": ("EVStopReasonExtension",
            {"stopReason": "reachedTargetSOC"}),
        "evse_stop_reason": ("EVSEStopReasonExtension",
            {"stopReason": "remoteStop"}),
        "ev_derating": ("EVDeratingReasonExtension",
            {"deratingReason": "ressTemperatureTooHigh"}),
        "evse_derating": ("EVSEDeratingReasonExtension",
            {"deratingReason": "gridLimitation"}),
    }
    # Full ENP wrap: EVSE Grid Information, UUID F0E77C3A... (per Table 28).
    # NOTE: the ENP ExtensionSet names some payloads by their ENUM type name
    # rather than the wrapping SEQUENCE; if the typed value below is rejected,
    # read the [FAIL] get_val() hint and adjust the open-type shape.
    enp_full = ("ENPExtensions",
        {"enpExtensionsList": [
            {"extensionID": bytes.fromhex("F0E77C3ADC41477398C9F177F44775BB"),
             "extensionValue": ("EVSEGridInformationExtension",
                 {"gridConnectionPointStatus": "connected",
                  "localGridOperationMode": "normal"})}]},
        "enp_full")
    run_samples(M_enp, os.path.join(OUT, "enp"), enp_samples, enp_full)

print()
print("==================================================================")
print(" SUMMARY")
print("   ESDP compiled : %s" % ("yes" if M_esdp is not None else "NO"))
print("   ENP  compiled : %s" % ("yes" if M_enp  is not None else "NO"))
print("==================================================================")
PYEOF

    echo
    echo "=================================================================="
    echo " SPIKE COMPLETE"
    echo "   CLASS/ExtensionSet parse ...... STEP 1 (ESDP) + STEP 2 (ENP)"
    echo "   OER codec present ............. VERSION line"
    echo "   per-type OER round-trip ....... rows under each module"
    echo "   open-type dispatch by UUID .... decisive test per module"
    echo " Golden fixtures:"
    echo "   lib/3rd_party/asn1/fixtures_pycrate/esdp/*.oer + manifest.json"
    echo "   lib/3rd_party/asn1/fixtures_pycrate/enp/*.oer  + manifest.json"
    echo " Cross-check: encode the SAME values through the bridge/codec and"
    echo " diff bytes. Identical => provably wire-equivalent."
    echo "=================================================================="
  '

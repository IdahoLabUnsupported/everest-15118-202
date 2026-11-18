#!/usr/bin/env bash
# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
#
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"

docker run --rm -i \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "${repo_root}":/work \
    ubuntu:24.04 bash -s <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    git ca-certificates build-essential autoconf automake libtool bison flex

cd /tmp
git clone --depth 1 https://github.com/vlm/asn1c.git
cd asn1c
autoreconf -iv >/dev/null 2>&1
./configure -q
make -j"$(nproc)" >/dev/null 2>&1
make install >/dev/null 2>&1

rm -rf /tmp/asn1-regen
mkdir -p /tmp/asn1-regen

make_codegen_asn() {
    in_file="$1"
    out_file="$2"
    module_name="$3"
    container_type="$4"
    list_field="$5"
    item_type="$6"

    if [ ! -f "$in_file" ]; then
        echo "Missing ASN.1 input: $in_file" >&2
        exit 1
    fi

    awk -v module_name="$module_name" \
        -v container_type="$container_type" \
        -v list_field="$list_field" \
        -v item_type="$item_type" '
        /^[A-Za-z0-9-]+ DEFINITIONS/ {
            print module_name " DEFINITIONS AUTOMATIC TAGS ::= BEGIN"
            next
        }

        $0 ~ "^" container_type " ::= SEQUENCE" {
            print container_type " ::= SEQUENCE {"
            print "  " list_field " SEQUENCE (SIZE (1..MAX)) OF " item_type ","
            print "  ..."
            print "}"
            skip_container = 1
            next
        }
        skip_container {
            if ($0 ~ /^}/) {
                skip_container = 0
            }
            next
        }

        $0 ~ "^" item_type " ::= SEQUENCE" {
            print item_type " ::= SEQUENCE {"
            print "  extensionID     OCTET STRING (SIZE (16)),"
            print "  extensionValue  OCTET STRING,"
            print "  ..."
            print "}"
            skip_item = 1
            next
        }
        skip_item {
            if ($0 ~ /^}/) {
                skip_item = 0
            }
            next
        }

        /^EXTENSION ::= CLASS/ {
            skip_class = 1
            next
        }
        skip_class {
            if ($0 ~ /WITH SYNTAX/) {
                skip_class = 0
            }
            next
        }

        /^ExtensionSet EXTENSION ::= \{/ {
            skip_set = 1
            next
        }
        skip_set {
            if ($0 ~ /^}/) {
                skip_set = 0
            }
            next
        }

        { print }
    ' "$in_file" > "$out_file"
}

make_codegen_asn \
    /work/lib/3rd_party/asn1/esdp_extensions.asn \
    /tmp/asn1-regen/esdp_extensions_codegen.asn \
    ESDPExtensionsCodegen \
    ESDPExtensions \
    esdpExtensionsList \
    ESDPExtension

make_codegen_asn \
    /work/lib/3rd_party/asn1/enp_extensions.asn \
    /tmp/asn1-regen/enp_extensions_codegen.asn \
    ENPExtensionsCodegen \
    ENPExtensions \
    enpExtensionsList \
    ENPExtension

cd /tmp/asn1-regen
asn1c -no-gen-example -fcompound-names \
    /tmp/asn1-regen/esdp_extensions_codegen.asn \
    /tmp/asn1-regen/enp_extensions_codegen.asn

generated_c_count="$(find /tmp/asn1-regen -maxdepth 1 -type f -name "*.c" | wc -l)"
generated_h_count="$(find /tmp/asn1-regen -maxdepth 1 -type f -name "*.h" | wc -l)"
if [ "$generated_c_count" -eq 0 ] || [ "$generated_h_count" -eq 0 ]; then
    echo "asn1c did not generate C/H outputs" >&2
    find /tmp/asn1-regen -maxdepth 1 -type f -printf "  %f\n" | sort >&2
    exit 1
fi
echo "asn1c generated ${generated_c_count} C files and ${generated_h_count} headers"

cd /work/lib/3rd_party/asn1

find . -maxdepth 1 -type f \( \
    -name "*.c" -o \
    -name "*.h" -o \
    -name "CMakeLists.txt" -o \
    -name "all_asn1c_headers.h" -o \
    -name "Makefile.am.libasncodec" \
\) -delete

find /tmp/asn1-regen -maxdepth 1 -type f \( \
    -name "*.c" -o \
    -name "*.h" -o \
    -name "Makefile.am.libasncodec" \
\) -exec cp -f {} . \;

{
    printf "add_library(asn1_modules\n"
    find . -maxdepth 1 -type f -name "*.c" -printf "%f\n" | sort | sed "s/^/\t/"
    printf ")\n\n"
    printf "target_include_directories(asn1_modules\n"
    printf "    PUBLIC\n"
    printf "      \${CMAKE_CURRENT_SOURCE_DIR}\n"
    printf ")\n\n"
    printf "target_compile_options(asn1_modules PRIVATE -Wno-incompatible-pointer-types)\n"
} > CMakeLists.txt

{
    printf "#ifndef ALL_ASN1C_HEADERS_H\n"
    printf "#define ALL_ASN1C_HEADERS_H\n"
    find . -maxdepth 1 -type f -name "*.h" ! -name "all_asn1c_headers.h" -printf "%f\n" | sort | sed "s/.*/#include \"&\"/"
    printf "#endif // ALL_ASN1C_HEADERS_H\n"
} > all_asn1c_headers.h

installed_c_count="$(find . -maxdepth 1 -type f -name "*.c" | wc -l)"
installed_h_count="$(find . -maxdepth 1 -type f -name "*.h" | wc -l)"
if [ "$installed_c_count" -eq 0 ] || [ "$installed_h_count" -eq 0 ]; then
    echo "Generated ASN.1 outputs were not copied into /work/lib/3rd_party/asn1" >&2
    exit 1
fi

chown "$HOST_UID:$HOST_GID" \
    ./*.c ./*.h ./CMakeLists.txt ./all_asn1c_headers.h ./Makefile.am.libasncodec

echo "DONE: installed ${installed_c_count} C files and ${installed_h_count} headers in /work/lib/3rd_party/asn1"
EOF

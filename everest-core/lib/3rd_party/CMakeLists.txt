# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
# This file has been modified from the original.

set(THIRDPARTY_INCLUDE_TMP_DIR ${LIB_INCLUDE_TMP_DIR}/3rd_party)
set(THIRDPARTY_INCLUDE_INSTALL_DIR ${LIB_INCLUDE_INSTALL_DIR}/3rd_party)

add_subdirectory(nanopb)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/asn1/CMakeLists.txt)
    add_subdirectory(asn1)
else()
    message(FATAL_ERROR
        "The ASN.1 codec sources (lib/3rd_party/asn1) have not been generated. "
        "Run lib/3rd_party/asn1/fetch_asn1.sh and regenerate_asn1c.sh first; "
        "see lib/3rd_party/asn1/README_ASN1.md.")
endif()

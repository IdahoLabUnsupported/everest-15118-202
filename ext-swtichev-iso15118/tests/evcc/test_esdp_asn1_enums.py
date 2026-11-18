# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""Regression tests for ESDP ASN.1 enum extraction."""

import pytest

from iso15118.evcc.asn1 import esdp_asn1_main


@pytest.mark.parametrize(
    ("type_name", "expected"),
    [
        (
            "SecurityProfile",
            {
                "tcpOnly": 0,
                "iso-15118-2-2014": 10,
                "iso-15118-2-2026": 11,
                "iso-15118-20-2022": 20,
            },
        ),
        (
            "AuthorizationMethod",
            {"eim": 0, "pnc-2": 10, "pnc-20": 20},
        ),
        (
            "ElectricalChargingSystem",
            {
                "iec61851-1-ed2": 1,
                "iec61851-1-ed3": 2,
                "iec61851-1-ed4": 3,
                "iec61851-23-ed1": 10,
                "iec61851-23-ed2": 11,
                "iec61851-23-ed3": 12,
                "iec61851-23-3-ed1": 20,
                "sae-j1772-201602": 30,
                "sae-j1772-201710": 31,
                "sae-j1772-202401": 32,
                "sae-j3068-202207": 40,
                "sae-j3068-202409": 41,
                "sae-j3400-202409": 50,
            },
        ),
    ],
)
def test_extensible_enum_values_ignore_asn1_extension_marker(type_name, expected):
    assert esdp_asn1_main._enum_values(type_name) == expected


def test_unknown_asn1tools_enum_representation_uses_text_fallback(monkeypatch):
    parsed_schema = {
        "TestModule": {
            "types": {
                "SecurityProfile": {
                    "values": [("tcpOnly", 0), ("unknown", object())],
                }
            }
        }
    }
    monkeypatch.setattr(esdp_asn1_main, "_parsed_schema", parsed_schema)

    assert esdp_asn1_main._enum_values("SecurityProfile") == {
        "tcpOnly": 0,
        "iso-15118-2-2014": 10,
        "iso-15118-2-2026": 11,
        "iso-15118-20-2022": 20,
    }

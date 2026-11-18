# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""Regression test for COER length-prefixing of ESDP UTF8String values."""

from iso15118.evcc.asn1 import esdp_asn1_main


def test_world_manufacturer_identifier_carries_a_coer_length_determinant():
    """X.696 clause 27: a UTF8String is length-prefixed even with a fixed SIZE.

    asn1tools omits the determinant for ``UTF8String (SIZE (3))``; the ESDP
    codec restores it so the WMI is ``03`` + three bytes, like every other
    UTF8String.
    """

    value = {"worldManufacturerIdentifier": "1HG"}

    encoded = esdp_asn1_main._schema.encode("EVCharacteristicsExtension", value)

    assert encoded.hex() == "00" + "03" + "1HG".encode().hex()
    assert esdp_asn1_main._schema.decode("EVCharacteristicsExtension", encoded) == value


def test_ev_characteristics_golden_vector():
    value = {"worldManufacturerIdentifier": "1HG", "evccSoftwareVersion": "1.0"}

    encoded = esdp_asn1_main._schema.encode("EVCharacteristicsExtension", value)

    assert encoded.hex() == "100331484703312e30"
    assert esdp_asn1_main._schema.decode("EVCharacteristicsExtension", encoded) == value

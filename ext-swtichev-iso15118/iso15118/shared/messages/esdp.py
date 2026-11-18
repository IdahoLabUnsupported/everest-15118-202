# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

import logging
from ipaddress import IPv6Address
from typing import Union

from iso15118.shared.exceptions import (
    InvalidESDPRequestError,
    InvalidESDPResponseError,
)
from iso15118.shared.messages.enums import (
    DINPayloadTypes,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
)
from iso15118.shared.messages.sdp import (
    MAX_TCP_PORT,
    MIN_TCP_PORT,
    SDPRequest,
    SDPRequestWireless,
    SDPResponse,
    SDPResponseWireless,
    Security,
    Transport,
)

logger = logging.getLogger(__name__)

ESDP_FIXED_PAYLOAD_LEN = 4


class ESDPSetupRequest:
    """
    The ESDP Setup Request (payload type 0x2021), first step of the ESDP
    two-step handshake per Table 2 of ISO/PAS 15118-202:2025.
    Payload: ESDP Version (2B) + Max V2GTP Message Size (2B) + Multiplexed ENP (1B)
    """

    def __init__(self, esdp_version: int, max_payload_size: int, multiplexed_enp: int):
        self.payload_type = ISOV2PayloadTypes.ESDP_SETUP_REQUEST
        self.esdp_version = esdp_version
        self.max_payload_size = max_payload_size
        self.multiplexed_enp = multiplexed_enp

    def to_payload(self) -> bytes:
        return (
            self.esdp_version.to_bytes(2, "big")
            + self.max_payload_size.to_bytes(2, "big")
            + self.multiplexed_enp.to_bytes(1, "big")
        )

    @staticmethod
    def from_payload(payload: bytes) -> "ESDPSetupRequest":
        if len(payload) != 5:
            logger.error(
                "ESDPSetupRequest payload must be 5 bytes. "
                f"Provided: {len(payload)} bytes ({payload.hex()})"
            )
            raise InvalidESDPRequestError
        return ESDPSetupRequest(
            int.from_bytes(payload[:2], "big"),
            int.from_bytes(payload[2:4], "big"),
            payload[4],
        )

    def __len__(self):
        return 5

    def __repr__(self):
        return (
            "["
            f"ESDPVersion: {self.esdp_version:#06x}"
            f", MaxPayloadSize: {self.max_payload_size}"
            f", MultiplexedENP: {self.multiplexed_enp}"
            "]"
        )


class ESDPSetupResponse:
    """
    The ESDP Setup Response (payload type 0x2022), SECC reply to ESDPSetupRequest
    per Table 2 of ISO/PAS 15118-202:2025.
    Payload: ESDP Version (2B) + Max V2GTP Message Size (2B) + Multiplexed ENP (1B)
    """

    def __init__(self, esdp_version: int, max_payload_size: int, multiplexed_enp: int):
        self.payload_type = ISOV2PayloadTypes.ESDP_SETUP_RESPONSE
        self.esdp_version = esdp_version
        self.max_payload_size = max_payload_size
        self.multiplexed_enp = multiplexed_enp

    def to_payload(self) -> bytes:
        return (
            self.esdp_version.to_bytes(2, "big")
            + self.max_payload_size.to_bytes(2, "big")
            + self.multiplexed_enp.to_bytes(1, "big")
        )

    @staticmethod
    def from_payload(payload: bytes) -> "ESDPSetupResponse":
        if len(payload) < 5:
            raise InvalidESDPResponseError(
                f"ESDPSetupResponse payload must be at least 5 bytes. "
                f"Provided: {len(payload)} bytes "
                f"({payload.hex() if isinstance(payload, bytes) else payload})"
            )
        payload = payload[:5]
        return ESDPSetupResponse(
            int.from_bytes(payload[:2], "big"),
            int.from_bytes(payload[2:4], "big"),
            payload[4],
        )

    def __len__(self):
        return 5

    def __repr__(self):
        return (
            "["
            f"ESDPVersion: {self.esdp_version:#06x}"
            f", MaxPayloadSize: {self.max_payload_size}"
            f", MultiplexedENP: {self.multiplexed_enp}"
            "]"
        )


def _parse_esdp_payload(payload: bytes, error_type):
    if len(payload) < ESDP_FIXED_PAYLOAD_LEN:
        raise error_type(
            "ESDP payload must be at least 4 bytes. "
            f"Provided: {len(payload)} bytes ({payload.hex()})"
        )

    esdp_version = int.from_bytes(payload[:2], "big")
    extensions_offset = int.from_bytes(payload[2:4], "big")
    extensions_start = ESDP_FIXED_PAYLOAD_LEN + extensions_offset
    if extensions_start > len(payload):
        raise error_type(
            "ESDP extensions offset points beyond payload: "
            f"offset={extensions_offset}, payload={len(payload)} bytes"
        )

    return (
        esdp_version,
        extensions_offset,
        payload[ESDP_FIXED_PAYLOAD_LEN:extensions_start],
        payload[extensions_start:],
    )


class ESDPRequest:
    def __init__(
        self,
        esdp_version,
        extensions_offset,
        esdp_extensions,
        esdp_offset_bytes=None,
    ):
        self.payload_type: Union[
            DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes
        ] = ISOV2PayloadTypes.ESDP_REQUEST
        self.esdp_version = esdp_version
        self.extensions_offset = extensions_offset  # [V2G202-0007]: 0x0000 for this edition
        self.esdp_offset_bytes = (
            bytes(extensions_offset)
            if esdp_offset_bytes is None
            else esdp_offset_bytes
        )
        if len(self.esdp_offset_bytes) != self.extensions_offset:
            raise ValueError(
                "ESDP offset byte count does not match extensions_offset: "
                f"{len(self.esdp_offset_bytes)} != {self.extensions_offset}"
            )
        self.esdp_extensions = esdp_extensions

    def to_payload(self) -> bytes:
        payload = (
            self.esdp_version.to_bytes(2, "big")
            + self.extensions_offset.to_bytes(2, "big")
            + self.esdp_offset_bytes
            + self.esdp_extensions
        )
        return payload

    @staticmethod
    def from_payload(payload: bytes) -> Union["ESDPRequest"]:
        try:
            (
                esdp_version,
                extensions_offset,
                esdp_offset_bytes,
                esdp_extensions,
            ) = _parse_esdp_payload(payload, InvalidESDPRequestError)

            return ESDPRequest(
                esdp_version,
                extensions_offset,
                esdp_extensions,
                esdp_offset_bytes,
            )
        except ValueError as exc:
            raise InvalidESDPRequestError from exc

    def __len__(self):
        return (
            ESDP_FIXED_PAYLOAD_LEN
            + len(self.esdp_offset_bytes)
            + len(self.esdp_extensions)
        )

    def __repr__(self):
        return (
            "["
            f"esdp_version: {self.esdp_version}"
            f", extensions_offset: {self.extensions_offset}"
            f", esdp_extensions: {self.esdp_extensions}"
            "]"
        )


class ESDPResponse:
    """
    The SECC Discovery Protocol Request message, which the SECC uses to
    respond to the EVCC's ESDPRequest.
    """

    def __init__(
        self,
        esdp_version: int,
        extensions_offset: int,
        ip_address: bytes,
        port: int,
        security: Security,
        transport_protocol: Transport,
        esdp_extensions: bytes = b"",
        esdp_offset_bytes=None,
    ):
        if len(ip_address) != 16:
            logger.error(
                f"Please provide a valid IPv6 address with 16 bytes. "
                f"Provided: {len(ip_address)} bytes "
                f"({ip_address.hex()})"
            )
            return

        if port < MIN_TCP_PORT or port > MAX_TCP_PORT:
            logger.warning(
                f"The port {port} does not match the mandatory "
                f"UDP server port 15118."
            )

        if security not in Security.options():
            logger.error(
                f"'{security}' is not a valid value for the "
                f"field 'security'."
                f"Allowed: {Security.options()} "
            )
            return

        if transport_protocol not in Transport.options():
            logger.error(
                f"'{transport_protocol}' is not a valid value for "
                f"the field 'transport_protocol'."
                f"Allowed: {Transport.options()} "
            )
            return

        self.esdp_version = esdp_version
        self.extensions_offset = extensions_offset  # [V2G202-0007]: 0x0000 for this edition
        self.esdp_offset_bytes = (
            bytes(extensions_offset)
            if esdp_offset_bytes is None
            else esdp_offset_bytes
        )
        if len(self.esdp_offset_bytes) != self.extensions_offset:
            raise ValueError(
                "ESDP offset byte count does not match extensions_offset: "
                f"{len(self.esdp_offset_bytes)} != {self.extensions_offset}"
            )
        self.ip_address = ip_address
        self.port = port
        self.security = security
        self.transport_protocol = transport_protocol
        self.esdp_extensions = esdp_extensions
        self.payload_type = ISOV2PayloadTypes.ESDP_RESPONSE

    def to_payload(self) -> bytes:
        payload = (
            self.esdp_version.to_bytes(2, "big")
            + self.extensions_offset.to_bytes(2, "big")
            + self.esdp_offset_bytes
            + self.esdp_extensions
        )
        return payload

    @staticmethod
    def from_payload(payload) -> "ESDPResponse":
        try:
            (
                esdp_version,
                extensions_offset,
                esdp_offset_bytes,
                esdp_extensions,
            ) = _parse_esdp_payload(payload, InvalidESDPResponseError)
            from iso15118.evcc.asn1 import esdp_asn1_main

            [prt, ipv6addr, sec] = esdp_asn1_main.decode_data(esdp_extensions)

            logger.info(f"SECC requested Security = {str(sec)}")

            if str(sec) == "tcpOnly":
                secint = 16  # TCP
            else:
                secint = 0  # TLS

            return ESDPResponse(
                esdp_version,
                extensions_offset,
                ipv6addr,  # IPv6 address
                int(prt),  # Port (now int from IPv6SocketTuple; was OCTET STRING pre-202)
                Security(secint),
                Transport(0),  # TCP
                esdp_extensions,
                esdp_offset_bytes,
            )
        except ValueError as exc:
            raise InvalidESDPResponseError from exc

    def __len__(self):
        return (
            ESDP_FIXED_PAYLOAD_LEN
            + len(self.esdp_offset_bytes)
            + len(self.esdp_extensions)
        )

    def __repr__(self):
        ip_address: str = IPv6Address(int.from_bytes(self.ip_address, "big")).compressed
        return (
            f"[ ESDP Version: {self.esdp_version}"
            f", Extensions Offset: {self.extensions_offset}"
            f", IP address: {ip_address}"
            f", Port: {str(self.port)} "
            f", Security: {self.security.name} "
            f", Transport: {self.transport_protocol.name} ]"
        )


def create_esdp_response(
    esdp_request: Union[SDPRequest, SDPRequestWireless, ESDPRequest],
    esdp_version: int,
    ip_address: bytes,
    port: int,
    tls_enabled: bool,
) -> Union[SDPResponse, SDPResponseWireless, ESDPResponse]:
    """
    Creates an ESDP response based on the incoming ESDP request.

    Args:
        esdp_request: The ESDP request received from the UDP client
        ip_address: The IP address of the TCP server
        port: The port of the TCP or TLS server
        tls_enabled: Indicates if a TLS enabled server is available on SECC

    Returns:
        An ESDPResponse, or an SDPResponse for compatibility with legacy callers.
    """
    esdp_response = None

    if tls_enabled:
        security = Security.TLS
    else:
        security = Security.NO_TLS

    if isinstance(esdp_request, SDPRequest):
        esdp_response = SDPResponse(ip_address, port, security, Transport.TCP)
    elif isinstance(esdp_request, ESDPRequest):
        esdp_response = ESDPResponse(
            esdp_version, 0, ip_address, port, security, Transport.TCP
        )
    elif isinstance(esdp_request, SDPRequestWireless):
        raise NotImplementedError("SDPRequestWireless is not yet implemented")
    else:
        logger.error("Invalid ESDP request, will ignore")

    return esdp_response

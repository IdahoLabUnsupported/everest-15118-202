# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""Regression tests for EVCC ESDP multicast loopback and receive filtering."""

from __future__ import annotations

import asyncio
import socket

from iso15118.evcc.transport.udp_client import UDPClient
from iso15118.shared.messages.enums import ISOV2PayloadTypes, Protocol
from iso15118.shared.messages.esdp import ESDPSetupRequest, ESDPSetupResponse
from iso15118.shared.messages.v2gtp import V2GTPMessage


def _message(payload_type, payload: bytes) -> bytes:
    return V2GTPMessage(Protocol.UNKNOWN, payload_type, payload).to_bytes()


def test_esdp_socket_disables_ipv6_multicast_loopback(monkeypatch):
    class _FakeSocket:
        def __init__(self):
            self.options = []

        def setsockopt(self, level, option, value):
            self.options.append((level, option, value))

        def bind(self, address):
            self.address = address

    sock = _FakeSocket()
    monkeypatch.setattr(socket, "socket", lambda **_kwargs: sock)
    monkeypatch.setattr(socket, "if_nametoindex", lambda _iface: 1)
    assert UDPClient._create_socket("lo") is sock
    assert (
        socket.IPPROTO_IPV6,
        socket.IPV6_MULTICAST_LOOP,
        0,
    ) in sock.options


async def test_receive_ignores_reflected_request_until_setup_response():
    handler_queue = asyncio.Queue()
    client = UDPClient(handler_queue, "lo")
    request = ESDPSetupRequest(0x0100, 1220, 0x00)
    response = ESDPSetupResponse(0x0100, 1220, 0x00)

    client.datagram_received(
        _message(ISOV2PayloadTypes.ESDP_SETUP_REQUEST, request.to_payload()),
        ("fe80::1", 15202),
    )
    client.datagram_received(
        _message(ISOV2PayloadTypes.ESDP_SETUP_RESPONSE, response.to_payload()),
        ("fe80::2", 15118),
    )
    client.datagram_received(
        _message(ISOV2PayloadTypes.ESDP_SETUP_RESPONSE, response.to_payload()),
        ("fe80::2", 15202),
    )

    await client.receive(
        0.05,
        "ESDPSetupReq",
        {ISOV2PayloadTypes.ESDP_SETUP_RESPONSE},
        15202,
    )

    packet = handler_queue.get_nowait()
    parsed = V2GTPMessage.from_bytes(Protocol.UNKNOWN, packet.data)
    assert parsed.payload_type == ISOV2PayloadTypes.ESDP_SETUP_RESPONSE


async def test_receive_times_out_after_only_unrelated_packets():
    handler_queue = asyncio.Queue()
    client = UDPClient(handler_queue, "lo")
    request = ESDPSetupRequest(0x0100, 1220, 0x00)
    client.datagram_received(
        _message(ISOV2PayloadTypes.ESDP_SETUP_REQUEST, request.to_payload()),
        ("fe80::1", 15202),
    )

    await client.receive(
        0.001,
        "ESDPSetupReq",
        {ISOV2PayloadTypes.ESDP_SETUP_RESPONSE},
    )

    notification = handler_queue.get_nowait()
    assert notification.message_name == "ESDPSetupReq"

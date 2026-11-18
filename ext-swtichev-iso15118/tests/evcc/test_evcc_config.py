# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from iso15118.evcc.comm_session_handler import CommunicationSessionHandler
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.evcc_config import EVCCConfig


def test_esdp_retry_cycles_defaults_to_35():
    assert EVCCConfig().esdp_retry_cycles == 35


def test_esdp_retry_cycles_can_be_configured_by_alias():
    assert EVCCConfig(esdpRetryCycles=7).esdp_retry_cycles == 7


def test_esdp_retry_cycles_rejects_negative_values():
    with pytest.raises(ValidationError):
        EVCCConfig(esdpRetryCycles=-1)


def test_session_handler_uses_configured_esdp_retry_cycles():
    config = EVCCConfig(esdpRetryCycles=7)
    codec = Mock()
    codec.get_version.return_value = "test"

    handler = CommunicationSessionHandler(
        config=config,
        iface="eth0",
        codec=codec,
        ev_controller=SimEVController(config),
    )

    assert handler._esdp_retry_cycles == 7

# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
# This file has been modified from the original.

"""
This module contains the EVCC's CommunicationSessionHandler class as well as
its EVCCCommunicationSession class. The former is used to initiate the EVCC
and handle the SDP (SECC Discovery Protocol) exchange with the EVCC, which - if
successful - will result in spawning up an EVCCCommunicationSession object.
That EVCCCommunicationSession object is taking care of the TCP communication
with the SECC to properly exchange all messages in a V2G communication session.
"""

import asyncio
import logging
from asyncio.streams import StreamReader, StreamWriter
from ipaddress import IPv6Address
from typing import Coroutine, List, Optional, Tuple, Union

from pydantic.error_wrappers import ValidationError

from iso15118.evcc import evcc_settings
from iso15118.evcc.controller.interface import EVControllerInterface
from iso15118.evcc.evcc_config import EVCCConfig
from iso15118.evcc.transport.tcp_client import TCPClient
from iso15118.evcc.transport.udp_client import UDPClient
from iso15118.shared.comm_session import V2GCommunicationSession
from iso15118.shared.exceptions import (
    InvalidESDPResponseError,
    InvalidSDPResponseError,
    InvalidSettingsValueError,
    InvalidV2GTPMessageError,
    MessageProcessingError,
    SDPFailedError,
)
from iso15118.shared.exi_codec import EXI
from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.messages.app_protocol import AppProtocol, SupportedAppProtocolReq
from iso15118.shared.messages.enums import (
    AuthEnum,
    DINPayloadTypes,
    EnergyTransferModeEnum,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Namespace,
    Protocol,
    UINT_32_MAX
)
from iso15118.shared.messages.esdp import (
    ESDPRequest,
    ESDPResponse,
    ESDPSetupRequest,
    ESDPSetupResponse,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ChargingSession as ChargingSessionV2,
)
from iso15118.shared.messages.iso15118_20.common_messages import AuthorizationReq
from iso15118.shared.messages.iso15118_20.common_messages import (
    ChargingSession as ChargingSessionV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    ScheduleExchangeReq,
    ScheduleExchangeRes,
)
from iso15118.shared.messages.iso15118_20.common_types import Processing
from iso15118.shared.messages.sdp import (
    SDPRequest,
    SDPResponse,
    Security,
    Transport,
)
from iso15118.shared.messages.timeouts import Timeouts
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.network import ESDP_SERVER_PORT
from iso15118.shared.notifications import (
    ReceiveTimeoutNotification,
    StopNotification,
    UDPPacketNotification,
)
from iso15118.shared.utils import cancel_task, wait_for_tasks

from iso15118.evcc.asn1 import esdp_asn1_main

logger = logging.getLogger(__name__)

ESDP_MAX_REQUEST_COUNTER = 5 
SDP_MAX_REQUEST_COUNTER = 50 
SUPPORTED_ESDP_VERSION_MAJOR = 0x01
ESDP_SETUP_AFTER_SDP_TIMEOUT = 0.25
ESDP_RESPONSE_TIMEOUT = 0.5
ESDP_PHASE_IDLE = "idle"
ESDP_PHASE_SETUP = "setup"
ESDP_PHASE_REQUEST = "request"
ESDP_PHASE_COMPLETE = "complete"
ESDP_PHASE_FAILED = "failed"


class EVCCCommunicationSession(V2GCommunicationSession):
    """
    The communication session object for the EVCC, which holds session-specific
    variables and also implements a pausing mechanism.
    """

    def __init__(
        self,
        transport: Tuple[StreamReader, StreamWriter],
        session_handler_queue: asyncio.Queue,
        evcc_config: EVCCConfig,
        iface: str,
        ev_controller: EVControllerInterface,
    ):
        # Need to import here to avoid a circular import error
        # pylint: disable=import-outside-toplevel
        from iso15118.evcc.states.sap_states import SupportedAppProtocol

        # TODO: There must be another way to do this than to pass the self
        # itself into the child. There are just a few attributes in these
        # class. If it is really necessary we can pass them into the child
        # From what I could see, we just use attributes of the V2GCommunication
        # Session, so we dont need to do this self injection, since self
        # is already injected by default on a child
        V2GCommunicationSession.__init__(
            self, transport, SupportedAppProtocol, session_handler_queue, self
        )

        self.config = evcc_config
        self.iface = iface
        # The EV controller that implements the interface EVControllerInterface
        self.ev_controller = ev_controller
        # The authorization option (called PaymentOption in ISO 15118-2) the
        # EVCC selected from the authorization options offered by the SECC
        self.selected_auth_option: Optional[AuthEnum] = None
        # The amount of ServiceDetailReq messages (with the particular service
        # id to request more details for) the EVCC needs to send after having
        # received the ServiceDiscoveryRes
        self.service_details_to_request: List[int] = []
        # Protocols supported by the EVCC as sent to the SECC via
        # the SupportedAppProtocolReq message
        self.supported_app_protocols: List[AppProtocol] = []
        # The Ongoing timer (given in seconds) starts running once the EVCC
        # receives a response with the field EVSEProcessing set to 'Ongoing'.
        # Once the timer is up, the EV will terminate the communication session.
        # A value >= 0 means the timer is running, a value < 0 means it stopped.
        self.ongoing_timer: float = -1
        # The Charge timer (in seconds) starts running once the EVCC
        # receives a PowerDeliveryRes with EVSEProcessing set to 'Finished'.
        # This timer counts up during a charge session, recording the duration.
        # When a charge session is paused or stopped, the timer is reset.
        # A value >= 0 means the timer is running, a value < 0 means it stopped.
        self.charging_session_timer: float = -1
        # The end of profile schedule marks the final departure time within
        # the profile_entry_schedule created for a PowerDeliveryReq. This
        # value, is used to mark when the 24 entry schedule has terminated.
        # See ISO 15118-2 Subclause 8.5.2.10 for details
        self.end_of_profile_schedule: int= -1
        self.departure_time: int = -1
        # Temporarily save the ScheduleExchangeReq, which need to be resent to the SECC
        # if the response message's EVSEProcessing field is set to "Ongoing"
        self.ongoing_schedule_exchange_req: Optional[ScheduleExchangeReq] = None
        # Whether the EV is still processing to calculate the EVPowerProfile.
        # That value is needed across states (ScheduleExchange and PowerDelivery)
        # (ISO 15118-20)
        self.ev_processing: Processing = Processing.FINISHED
        # Temporarily save the ScheduleExchangeRes, in case the EVProcessing field of
        # PowerDeliveryReq is set to "Ongoing", so we can access that response in the
        # following PowerDelivery state (ISO 15118-20)
        self.schedule_exchange_res: Optional[ScheduleExchangeRes] = None
        # Whether to pause or terminate a charging session. Is set when sending
        # a PowerDeliveryReq (ISO 15118-2)
        self.charging_session_stop_v2: Optional[ChargingSessionV2] = None
        # Whether to pause, standby or terminate a charging session. Is set when sending
        # a PowerDeliveryReq (ISO 15118-20)
        self.charging_session_stop_v20: Optional[ChargingSessionV20] = None
        # Whether a renegotiation was requested by the SECC (with either
        # a MeteringReceiptRes, ChargingStatusRes, or CurrentDemandRes) or EVCC
        self.renegotiation_requested = False
        # The ID of the EVSE that controls the power flow to the EV
        self.evse_id: str = ""
        # "Caching" authorization_req. (Required in ISO15118-20)
        # Avoids recomputing the signature, eim, pnc params during authorization loop.
        self.authorization_req_message: Optional[AuthorizationReq] = None
        # The energy mode the EVCC selected (ISO 15118-2)
        self.selected_energy_mode: Optional[EnergyTransferModeEnum] = None
        self.is_tls = False

        self.sae_j2847_active: int = 0

    def create_sap(self) -> Union[SupportedAppProtocolReq, None]:
        """
        Sends a Supported App Protocol Request (SAP Request) via TCP to the
        SECC to agree upon a mutually supported communication protocol
        (an application layer protocol handshake).
        After receiving the SAP Response, the EVCC will change state to
        SupportedAppProtocol and process the message accordingly.

        Returns:
            A SupportedAppProtocolReq (request) message
        """
        app_protocols = []
        schema_id = 0
        priority = 0
        supported_protocols = self.config.supported_protocols

        # [V2G-DC-618] For DC charging according to DIN SPEC 70121,
        # an SDP server shall send an SECC Discovery Response message with Transport
        # Protocol equal to “TCP” and Security equal to “No transport layer security”
        # according to Table 23. Remove it from the supported protocols list if
        # use_tls is enabled
        if self.is_tls:
            try:
                supported_protocols.remove(Protocol.DIN_SPEC_70121)
                logger.warning(
                    "Removed DIN_SPEC from the list of supported Protocols as "
                    "TLS is enabled"
                )
            except ValueError:
                pass

        for protocol in supported_protocols:
            # A SchemaID (schema_id) is simply a running counter, enabling the
            # SECC to refer to a specific entry. It can, in principle, be
            # randomly chosen by the EVCC as long as it's in the value range of
            # one byte (=255). Each app_protocol_entry must have a different
            # schema_id and max. 20 app_protocol_entry elements are allowed
            # according to ISO 15118 and DIN SPEC 70121.
            #
            # We start by assigning the number 1 to the first entry and simply
            # increase the counter by 1 for each following entry.
            #
            # To enforce a specific priority of protocols, make sure to list
            # them in descending order in evcc_settings.SUPPORTED_PROTOCOLS
            schema_id += 1
            priority += 1
            app_protocol_entry = AppProtocol(
                protocol_ns=protocol.ns.value,
                major_version=(
                    2
                    if protocol in [Protocol.ISO_15118_2, Protocol.DIN_SPEC_70121]
                    else 1
                ),
                minor_version=0,
                schema_id=schema_id,
                priority=priority,
            )
            app_protocols.append(app_protocol_entry)

        self.supported_app_protocols = app_protocols
        sap_req = SupportedAppProtocolReq(app_protocol=self.supported_app_protocols)

        return sap_req

    async def send_sap(self):
        """
        Sends the Supported App Protocol Request

        Raises:
            MessageProcessingError, in case the instantiation of a
            SupportedAppProtocolRequest fails
        """
        try:
            sap_req = self.create_sap()
        except ValidationError as exc:
            logger.exception(
                "Validation error occurred while creating "
                f"SupportedAppProtocolReq: {exc}"
            )
            raise MessageProcessingError("SupportedAppProtocolReq") from exc

        v2gtp_msg = V2GTPMessage(
            Protocol.UNKNOWN,
            ISOV2PayloadTypes.EXI_ENCODED,
            EXI().to_exi(sap_req, Namespace.SAP),
        )
        self.current_state.message = sap_req
        await self.send(v2gtp_msg)

    def save_session_info(self):
        """
        Saves the values that need to be persisted during a charging pause
        according to section 8.4.2 in ISO 15118-2
        TODO Check what needs to happen in a pause with ISO 15118-20
        """
        logger.debug(
            "Writing session variables to settings for use when "
            "resuming the communication session later"
        )

        # === PAUSING RELATED INFORMATION ===
        # If a charging session needs to be paused, the EVCC needs to persist certain
        # information that must be provided again once the communication session
        # resumes. This information includes:
        # - Session ID: int or None
        # - Selected authorization option: must be a member of AuthEnum enum or None
        # - Requested energy transfer mode: must be a member of EnergyTransferModeEnum
        #                                   or None
        # TODO Check what ISO 15118-20 demands for pausing

        # TODO: save the settings into redis
        # RESUME_SESSION_ID = self.session_id
        # RESUME_SELECTED_AUTH_OPTION = self.selected_auth_option
        # RESUME_REQUESTED_ENERGY_MODE = self.selected_energy_mode
        
        evcc_settings.ev_session_context.session_id = self.session_id
        evcc_settings.ev_session_context.selected_auth_option = self.selected_auth_option
        evcc_settings.ev_session_context.requested_energy_mode = self.selected_energy_mode
        evcc_settings.ev_session_context.selected_energy_service = self.selected_energy_service

class CommunicationSessionHandler:
    """
    The CommunicationSessionHandler is the control center that manages the
    communication session with the SECC.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        config: EVCCConfig,
        iface: str,
        codec: IEXICodec,
        ev_controller: EVControllerInterface,
    ):
        self.list_of_tasks: List[Coroutine] = []
        self.udp_client: UDPClient = None
        self.tcp_client: TCPClient = None
        self.tls_client: bool = None
        self.config: EVCCConfig = config
        self.iface: str = iface
        self.ev_controller: EVControllerInterface = ev_controller
        self.esdp_retries_number = ESDP_MAX_REQUEST_COUNTER
        self.sdp_retries_number = SDP_MAX_REQUEST_COUNTER
        self._sdp_retry_cycles = self.config.sdp_retry_cycles
        self._esdp_retry_cycles = self.config.esdp_retry_cycles
        # Stores the SECC's source address from ESDPSetupRes for unicast ESDPReq
        self.secc_esdp_addr: Optional[tuple] = None
        self.secc_esdp_max_payload_size: Optional[int] = None
        self.esdp_phase = ESDP_PHASE_IDLE
        self.esdp_request_first_sent_at: Optional[float] = None
        self.sdp_response_first_received_at: Optional[float] = None
        self.pending_sdp_response: Optional[Tuple[IPv6Address, int, bool]] = None

        # Set the selected EXI codec implementation
        EXI().set_exi_codec(codec)

        # Receiving queue for UDP client to notify about incoming datagrams
        self._rcv_queue: asyncio.Queue = asyncio.Queue(0)

        # The communication session is a tuple containing the session itself
        # and the associated task, so we can cancel the task when needed
        self.comm_session: Tuple[
            Optional[V2GCommunicationSession], Optional[asyncio.Task]
        ] = (None, None)

    async def start_session_handler(self):
        """
        This method is necessary, because python does not allow
        async def __init__. Therefore, we need to create a separate async
        method to be our constructor.
        """
        self.udp_client = UDPClient(self._rcv_queue, self.iface)
        self.list_of_tasks = [
            self.udp_client.start(),
            self.get_from_rcv_queue(self._rcv_queue),
            self.restart_sdp(True),
        ]

        logger.info("Communication session handler started")

        await wait_for_tasks(self.list_of_tasks)

    async def send_sdp(self):
        """
        Sends an SECC Discovery Protocol Request (SDP Request) via UDP to
        the SECC to retrieve the IP address and port of the SECC so that we
        can establish a TCP connection to the SECC's TCP server, given the
        IP address and port contained in the SDP Response
        """
        # the following loop is to allow the synchronization of the udp client
        # and the task to handle the SDP restart
        while not self.udp_client.started:
            await asyncio.sleep(0.1)
        security = Security.NO_TLS
        if self.config.use_tls:
            security = Security.TLS
        sdp_request = SDPRequest(security=security, transport_protocol=Transport.TCP)
        v2gtp_msg = V2GTPMessage(
            Protocol.UNKNOWN, sdp_request.payload_type, sdp_request.to_payload()
        )
        logger.info(f"Sending SDPRequest: {sdp_request}")
        await self.udp_client.send_and_receive(v2gtp_msg)

    async def send_esdp_setup(self):
        """
        Sends an ESDPSetupRequest (0x2021) to the SECC multicast address as the
        first step of the ESDP two-step handshake per ISO/PAS 15118-202:2025.
        """
        while not self.udp_client.started:
            await asyncio.sleep(0.1)

        esdp_setup_request = ESDPSetupRequest(
            esdp_version=0x0100,
            max_payload_size=0xFFFF,
            multiplexed_enp=0x00,
        )
        logger.info(f"Sending ESDPSetupRequest: {esdp_setup_request}")
        v2gtp_msg = V2GTPMessage(
            Protocol.UNKNOWN,
            ISOV2PayloadTypes.ESDP_SETUP_REQUEST,
            esdp_setup_request.to_payload(),
        )
        await self.udp_client.send_and_receive_esdp(v2gtp_msg)

    def _esdp_security_profiles(self) -> List[int]:
        if not (self.config.use_tls or self.config.enforce_tls):
            return [esdp_asn1_main.SECURITY_PROFILE_TCP_ONLY]

        supported_protocols = self.config.supported_protocols or []
        security_profiles = []
        if Protocol.ISO_15118_2 in supported_protocols:
            security_profiles.append(
                esdp_asn1_main.SECURITY_PROFILE_ISO_15118_2_2014
            )
        if any(
            protocol.name.startswith("ISO_15118_20")
            for protocol in supported_protocols
        ):
            security_profiles.append(
                esdp_asn1_main.SECURITY_PROFILE_ISO_15118_20_2022
            )

        if not security_profiles:
            security_profiles.append(
                esdp_asn1_main.SECURITY_PROFILE_ISO_15118_2_2014
            )
        return security_profiles

    def _esdp_is_active(self) -> bool:
        return self.esdp_phase in [ESDP_PHASE_SETUP, ESDP_PHASE_REQUEST]

    def _esdp_setup_timed_out_after_sdp(self) -> bool:
        if self.sdp_response_first_received_at is None:
            return False
        elapsed = asyncio.get_running_loop().time() - self.sdp_response_first_received_at
        return elapsed >= ESDP_SETUP_AFTER_SDP_TIMEOUT

    def _esdp_response_timed_out(self) -> bool:
        if self.esdp_request_first_sent_at is None:
            return False
        elapsed = asyncio.get_running_loop().time() - self.esdp_request_first_sent_at
        return elapsed >= ESDP_RESPONSE_TIMEOUT

    def _reset_esdp_cycle(self):
        self.secc_esdp_addr = None
        self.secc_esdp_max_payload_size = None
        self.esdp_phase = ESDP_PHASE_SETUP
        self.esdp_request_first_sent_at = None
        self.sdp_response_first_received_at = None
        self.pending_sdp_response = None

    async def _continue_with_pending_sdp_response(self) -> bool:
        if self.pending_sdp_response is None:
            return False

        host, port, secc_signals_tls = self.pending_sdp_response
        self.pending_sdp_response = None
        await self.start_comm_session(host, port, secc_signals_tls)
        return True

    async def _fail_esdp_and_continue_with_sdp(self):
        self.esdp_phase = ESDP_PHASE_FAILED
        if await self._continue_with_pending_sdp_response():
            return
        if self.sdp_retries_number > 0:
            await self.send_sdp()
            logger.info("Sending regular SDP Request")
            self.sdp_retries_number -= 1

    async def _retry_esdp_setup_or_continue_with_sdp(self):
        if self._esdp_setup_timed_out_after_sdp():
            await self._fail_esdp_and_continue_with_sdp()
            return
        try:
            await self.restart_sdp(False)
        except SDPFailedError as exc:
            logger.exception(exc)

    async def _retry_esdp_request_or_continue_with_sdp(self):
        if self._esdp_response_timed_out():
            await self._fail_esdp_and_continue_with_sdp()
            return
        try:
            await self.send_esdp()
        except InvalidSettingsValueError as exc:
            logger.error(
                f"Invalid value for {exc.entity} setting "
                f"{exc.setting}: {exc.invalid_value}"
            )

    async def send_esdp(self):
        """
        Sends an ESDPRequest (0x2023) to the SECC's unicast IPv6 address as the
        second step of the ESDP handshake. Must be called after receiving
        ESDPSetupResponse so that secc_esdp_addr is populated.
        """
        while not self.udp_client.started:
            await asyncio.sleep(0.1)

        security_profiles = self._esdp_security_profiles()

        energy_mode = (
            self.config.energy_transfer_mode.value
            if hasattr(self.config.energy_transfer_mode, "value")
            else str(self.config.energy_transfer_mode or "")
        )
        service_names = {
            service.name if hasattr(service, "name") else str(service)
            for service in (self.config.supported_energy_services or [])
        }
        supports_ac_charging = energy_mode.startswith("AC_") or any(
            service_name.startswith("AC") for service_name in service_names
        )
        supports_dc_charging = energy_mode.startswith("DC_") or any(
            service_name.startswith("DC") or service_name.startswith("MCS")
            for service_name in service_names
        )
        logger.info(
            "ESDP charging support: energyTransferMode=%s supportedEnergyServices=%s "
            "supportsDC=%s supportsAC=%s",
            energy_mode,
            sorted(service_names),
            supports_dc_charging,
            supports_ac_charging,
        )

        esdp_extensions, file_size = esdp_asn1_main.encode_data(
            security_profiles,
            charging_interface=self.config.charging_interface,
            interface_type=self.config.interface_type,
            electrical_charging_systems=self.config.electrical_charging_systems,
            control_pilot_bcb_toggle_support=self.config.control_pilot_bcb_toggle_support,
            max_contactor_celsius_temperature=self.config.max_contactor_celsius_temperature,
            supports_dc_charging=supports_dc_charging,
            supports_ac_charging=supports_ac_charging,
            ac_nominal_voltages=self.config.ac_nominal_voltages,
            ac_number_of_phases=self.config.ac_number_of_phases,
            ac_grid_frequencies=self.config.ac_grid_frequencies,
            ev_world_manufacturer_identifier=self.config.ev_world_manufacturer_identifier,
            ev_vehicle_descriptor_section=self.config.ev_vehicle_descriptor_section,
            ev_vehicle_indicator_section=self.config.ev_vehicle_indicator_section,
            evcc_software_version=self.config.evcc_software_version,
            emsp_info=self.config.emsp_info,
        )
        logger.info(f"ESDP packet size is {file_size} bytes")

        esdp_request = ESDPRequest(
            esdp_version=0x0100,
            extensions_offset=0x0000,
            esdp_extensions=esdp_extensions,
        )
        logger.info(f"Sending ESDPRequest: {esdp_request}")
        v2gtp_msg = V2GTPMessage(
            Protocol.UNKNOWN, ISOV2PayloadTypes.ESDP_REQUEST, esdp_request.to_payload()
        )
        if (
            self.secc_esdp_max_payload_size is not None
            and len(v2gtp_msg.to_bytes()) > self.secc_esdp_max_payload_size
        ):
            logger.error(
                "ESDPRequest size %d exceeds SECC maximum V2GTP message size %d",
                len(v2gtp_msg.to_bytes()),
                self.secc_esdp_max_payload_size,
            )
            await self._fail_esdp_and_continue_with_sdp()
            return

        self.esdp_phase = ESDP_PHASE_REQUEST
        if self.esdp_request_first_sent_at is None:
            self.esdp_request_first_sent_at = asyncio.get_running_loop().time()

        if self.secc_esdp_addr:
            await self.udp_client.send_and_receive_esdp_unicast(v2gtp_msg, self.secc_esdp_addr)
        else:
            logger.warning("secc_esdp_addr not set, falling back to multicast ESDPReq")
            await self.udp_client.send_and_receive_esdp(v2gtp_msg)

    async def restart_sdp(self, new_sdp_cycle: bool):
        """
        Initiates a new SECC Discovery Protocol (SDP) request message, which the
        EVCC sends to the SECC via UDP.

        The SDP messages are sent via UDP and the EVCC expects an SDP response
        from the SECC within 250 ms. If the EVCC runs into a timeout, it will
        send another SDP request. Up to 49 retries (50 SDP requests in total)
        are allowed before the SDP is deemed unsuccessful. As a result,
        the ISO 15118 communication cannot proceed and the EV would have to
        fall back to analog PWM (Pulse Width Modulation) based charging.

        The constant SDP_MAX_REQUEST_COUNTER is used to compare the current
        SDP request counter with the maximum allowed number of SDP requests in
        one go (35).

        However, once SDP was successful and the ISO 15118 communication
        proceeds, an error can occur later while processing one of the messages.
        It is up to the car manufacturer to decide how many times the EV should
        try to restart the communication, starting with the SDP. The rationale
        here is that this same error might not occur twice (maybe there was an
        unfortunate bit flip, for example).

        For restarting an SDP, we use the SDP_RETRY_CYCLES setting in the
        evcc_settings.py file. One SDP_RETRY_CYCLE can send up to 50 SDP
        consecutive requests before the cycle is over.

        Args:
            new_sdp_cycle:  True, if a new SDP cycle shall be initiated, which
                            would be the case if the previous SDP cycle resulted
                            in a V2GCommunicationSession and that session was
                            terminated. False, if a timeout occurred while
                            waiting for the SDP response, which triggers sending
                            another SDP request until SDP_MAX_REQUEST_COUNTER
                            is reached.

        Raises:
            SDPFailedError
        """
        shutdown_msg = (
            "ESDP and SDP failed to setup communication. Shutting down high-level communication. Unplug and "
            "plug in the cable again if you want to start anew."
        )

        if new_sdp_cycle:
            if self._esdp_retry_cycles == 0:
                raise SDPFailedError(
                    "EVCC tried to initiate a V2GCommunicationSession, "
                    "but maximum number of ESDP retry cycles "
                    f"({self.config.esdp_retry_cycles}) is now reached. "
                    f"{shutdown_msg}"
                )

            self._esdp_retry_cycles -= 1
            self.esdp_retries_number = ESDP_MAX_REQUEST_COUNTER
            self._reset_esdp_cycle()
            logger.debug(
                "Initiating new ESDP cycle, "
                f"{self._esdp_retry_cycles} more cycles(s) left"
            )

        if self.esdp_retries_number > 0:
            logger.info(f"Remaining ESDP requests: {self.esdp_retries_number}")
            try:
                await self.send_esdp_setup()
                logger.info("Sending ESDP Setup Request")
            except InvalidSettingsValueError as exc:
                logger.error(
                    f"Invalid value for {exc.entity} setting "
                    f"{exc.setting}: {exc.invalid_value}"
                )

            self.esdp_retries_number -= 1
        else:
            logger.error("Failed ESDP, now re-trying using SDP.")
            self.esdp_phase = ESDP_PHASE_FAILED
            if await self._continue_with_pending_sdp_response():
                return
            if self.sdp_retries_number > 0:
                await self.send_sdp()
                logger.info("Sending regular SDP Request")
                self.sdp_retries_number-=1

            else:       
                raise SDPFailedError(f"SDPRequest was not successful. " f"{shutdown_msg}")

    async def start_comm_session(self, host: IPv6Address, port: int, is_tls: bool):
        server_type = "TLS" if is_tls else "TCP"

        try:
            logger.info(
                f"Starting {server_type} client, trying to connect to "
                f"{host.compressed} at port {port} ..."
            )
            self.tcp_client = await TCPClient.create(
                host, port, self._rcv_queue, is_tls, self.iface
            )
            logger.info("TCP client connected")
        except Exception as exc:
            logger.exception(
                f"{exc.__class__.__name__} when trying to connect "
                f"to host {host} and port {port}"
            )
            return

        comm_session = EVCCCommunicationSession(
            (self.tcp_client.reader, self.tcp_client.writer),
            self._rcv_queue,
            self.config,
            self.iface,
            self.ev_controller,
        )
        # Overwriting is_tls field in EVCCCommunicationSession with the setting
        # returned from SDP response. Remember is_tls field in config still represents
        # the value initially provided in evcc_config.
        comm_session.is_tls = is_tls

        try:
            await comm_session.send_sap()
            self.comm_session = comm_session, asyncio.create_task(
                comm_session.start(Timeouts.SUPPORTED_APP_PROTOCOL_REQ)
            )
        except MessageProcessingError as exc:
            logger.exception(
                f"{exc.__class__.__name__} occurred while trying to "
                f"create create an SDPRequest"
            )
            return

    async def process_incoming_udp_packet(self, message: UDPPacketNotification):
        """
        We expect this to be an SDP response from the UDP server.
        Let's first check if it could be an SDP response with or without PPD
        (pairing and positioning device -> ACD-pantograph in ISO 15118-20)

        Args:
            message:    The UDPPacket containing an SDP response message
        """
        try:
            v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, message.data)
        except InvalidV2GTPMessageError as exc:
            logger.error(exc)
            return

        if v2gtp_msg.payload_type in [
            ISOV2PayloadTypes.SDP_RESPONSE,
            DINPayloadTypes.SDP_RESPONSE,
        ]:
            try:
                sdp_response = SDPResponse.from_payload(v2gtp_msg.payload)
            except InvalidSDPResponseError as exc:
                logger.error(exc)
                try:
                    await self.restart_sdp(True)
                    return
                except SDPFailedError as exc:
                    logger.exception(exc)
                    return  # TODO check if this is correct here

            logger.info(f"SDPResponse received: {sdp_response}")

            secc_signals_tls = False
            if sdp_response.security == Security.TLS:
                secc_signals_tls = True

            # The idea here is to use both the USE_TLS and ENFORCE_TLS setting of the
            # EVCC. USE_TLS can be used to set the Security byte field of the SDP
            # request to either 0x00 (TLS) or 0x10 (no NO_TLS). It's basically there
            # just to test both use cases.
            #
            # The ENFORCE_SECURITY setting can be used by the EV OEM to make sure the EV
            # only accepts TLS-secured communication sessions, if set to True. If set
            # to False, and USE_TLS is set to True, then the EVCC can also accept an
            # unsecure communication (triggered by the SECC sending an SDP response with
            # the Security byte field set to 0x10 (no NO_TLS)).
            #
            # The rationale behind this might be that the EV OEM trades convenience
            # (the EV driver can always charge) over security.
            if (not secc_signals_tls and self.config.enforce_tls) or (
                secc_signals_tls and not self.config.use_tls
            ):
                logger.error(
                    "Security mismatch, can't initiate communication session."
                    f"\nEVCC setting USE_TLS: {self.config.use_tls}"
                    f"\nEVCC setting ENFORCE_TLS: {self.config.enforce_tls}"
                    f"\nSDP response signals TLS: {secc_signals_tls}"
                )
                return

            ip_address_int = int.from_bytes(sdp_response.ip_address, "big")
            host = IPv6Address(ip_address_int)
            port = sdp_response.port
            if self._esdp_is_active():
                if self.sdp_response_first_received_at is None:
                    self.sdp_response_first_received_at = (
                        asyncio.get_running_loop().time()
                    )
                self.pending_sdp_response = (host, port, secc_signals_tls)
                logger.info("SDPResponse deferred until ESDP finishes")
                if self.esdp_phase == ESDP_PHASE_SETUP:
                    await self._retry_esdp_setup_or_continue_with_sdp()
                elif self.esdp_phase == ESDP_PHASE_REQUEST:
                    await self._retry_esdp_request_or_continue_with_sdp()
                return

        elif v2gtp_msg.payload_type == ISOV2PayloadTypes.ESDP_SETUP_RESPONSE:
            if self.esdp_phase != ESDP_PHASE_SETUP:
                logger.info("Ignoring ESDPSetupResponse outside ESDP setup phase")
                return
            try:
                esdp_setup_response = ESDPSetupResponse.from_payload(v2gtp_msg.payload)
            except InvalidESDPResponseError as exc:
                logger.error(exc)
                await self._retry_esdp_setup_or_continue_with_sdp()
                return

            if (esdp_setup_response.esdp_version >> 8) > SUPPORTED_ESDP_VERSION_MAJOR:
                logger.info(
                    "Ignoring ESDPSetupResponse with unsupported ESDP version %#06x",
                    esdp_setup_response.esdp_version,
                )
                await self._retry_esdp_setup_or_continue_with_sdp()
                return

            logger.info(f"ESDPSetupResponse received: {esdp_setup_response}")
            self.secc_esdp_addr = (
                message.addr[0],
                ESDP_SERVER_PORT,
                *message.addr[2:],
            )
            self.secc_esdp_max_payload_size = esdp_setup_response.max_payload_size
            logger.info(f"SECC ESDP address stored: {self.secc_esdp_addr}")
            try:
                await self.send_esdp()
            except InvalidSettingsValueError as exc:
                logger.error(
                    f"Invalid value for {exc.entity} setting "
                    f"{exc.setting}: {exc.invalid_value}"
                )
            return

        elif v2gtp_msg.payload_type in [
            ISOV2PayloadTypes.ESDP_RESPONSE,
        ]:
            if self.esdp_phase != ESDP_PHASE_REQUEST:
                logger.info("Ignoring ESDPResponse outside ESDP request phase")
                return
            try:
                esdp_response = ESDPResponse.from_payload(v2gtp_msg.payload)
            except InvalidESDPResponseError as exc:
                logger.error(exc)
                await self._retry_esdp_request_or_continue_with_sdp()
                return

            logger.info(f"ESDPResponse received: {esdp_response}")
            self.esdp_phase = ESDP_PHASE_COMPLETE
            self.pending_sdp_response = None

            secc_signals_tls = False
            if esdp_response.security == Security.TLS:
                secc_signals_tls = True

            # The idea here is to use both the USE_TLS and ENFORCE_TLS setting of the
            # EVCC. USE_TLS can be used to set the Security byte field of the SDP
            # request to either 0x00 (TLS) or 0x10 (no NO_TLS). It's basically there
            # just to test both use cases.
            #
            # The ENFORCE_SECURITY setting can be used by the EV OEM to make sure the EV
            # only accepts TLS-secured communication sessions, if set to True. If set
            # to False, and USE_TLS is set to True, then the EVCC can also accept an
            # unsecure communication (triggered by the SECC sending an SDP response with
            # the Security byte field set to 0x10 (no NO_TLS)).
            #
            # The rationale behind this might be that the EV OEM trades convenience
            # (the EV driver can always charge) over security.
            if (not secc_signals_tls and self.config.enforce_tls):
                logger.error(
                    "Security mismatch, can't initiate communication session."
                    f"\nEVCC setting USE_TLS: {self.config.use_tls}"
                    f"\nEVCC setting ENFORCE_TLS: {self.config.enforce_tls}"
                    f"\nSDP response signals TLS: {secc_signals_tls}"
                )
                return
            # for esdp, multiple security profiles can be offered
            # the esdp decode_data function currently returns security = TLS if TLS is one of the options
            # if only TLS is offered by SECC, this change will cause the EVCC to attempt a TCP connection which should get rejected
            elif(secc_signals_tls and not self.config.use_tls):
                secc_signals_tls = False


            ip_address_int = int.from_bytes(esdp_response.ip_address, "big")
            host = IPv6Address(ip_address_int)
            port = esdp_response.port

        elif v2gtp_msg.payload_type == ISOV20PayloadTypes.SDP_RESPONSE_WIRELESS:
            raise NotImplementedError(
                "The incoming datagram seems to be a SDPResponse "
                "for wireless communication (used for ACD-P). "
                "This feature is not yet implemented."
            )
        elif v2gtp_msg.payload_type in [
            ISOV2PayloadTypes.ESDP_SETUP_REQUEST,
            ISOV2PayloadTypes.ESDP_REQUEST,
        ]:
            logger.debug(
                "Ignoring reflected or unrelated ESDP request payload type %#06x",
                v2gtp_msg.payload_type,
            )
            return
        else:
            logger.error(
                f"Incoming datagram of {len(message)} bytes is no "
                f"valid SDPResponse message"
            )
            try:
                await self.restart_sdp(True)
            except SDPFailedError as exc:
                logger.exception(exc)
                return  # TODO check if this is correct here
            return

        await self.start_comm_session(host, port, secc_signals_tls)

    async def process_receive_timeout(self, notification: ReceiveTimeoutNotification):
        if notification.message_name == "ESDPSetupReq":
            if self.esdp_phase != ESDP_PHASE_SETUP:
                return
            if self._esdp_setup_timed_out_after_sdp():
                logger.info(
                    "ESDPSetupResponse not received within %.0f ms after SDPResponse; "
                    "continuing with SDP",
                    ESDP_SETUP_AFTER_SDP_TIMEOUT * 1000,
                )
                await self._fail_esdp_and_continue_with_sdp()
                return
            try:
                await self.restart_sdp(False)
            except SDPFailedError as exc:
                logger.exception(exc)
            return

        if notification.message_name == "ESDPReq":
            if self.esdp_phase != ESDP_PHASE_REQUEST:
                return
            if self._esdp_response_timed_out():
                logger.info(
                    "ESDPResponse not received within %.0f ms after first ESDPReq; "
                    "continuing with SDP",
                    ESDP_RESPONSE_TIMEOUT * 1000,
                )
                await self._fail_esdp_and_continue_with_sdp()
                return
            try:
                await self.send_esdp()
            except InvalidSettingsValueError as exc:
                logger.error(
                    f"Invalid value for {exc.entity} setting "
                    f"{exc.setting}: {exc.invalid_value}"
                )
            return

        try:
            await self.restart_sdp(False)
        except SDPFailedError as exc:
            logger.exception(exc)

    async def get_from_rcv_queue(self, queue: asyncio.Queue):
        """
        Waits for an incoming message from the UDP server or a notification
        from an ongoing EVCCCommunicationSession instance (e.g. ReceiveTimeout
        or a notification to pause or terminate the session).
        It will then be further processed accordingly.
        """
        while True:
            try:
                notification = queue.get_nowait()
            except asyncio.QueueEmpty:
                notification = await queue.get()

            try:
                if isinstance(notification, UDPPacketNotification):
                    await self.process_incoming_udp_packet(notification)
                elif isinstance(notification, ReceiveTimeoutNotification):
                    await self.process_receive_timeout(notification)
                elif isinstance(notification, StopNotification):
                    await cancel_task(self.comm_session[1])
                    del self.comm_session
                    if notification.successful:
                        break
                    else:
                        try:
                            await self.restart_sdp(True)
                        except SDPFailedError as exc:
                            logger.exception(exc)
                            # TODO not sure what else to do here
                    break
                else:
                    logger.warning(
                        "Communication session handler received "
                        "an unknown message or notification: "
                        f"{notification}"
                    )
            finally:
                queue.task_done()

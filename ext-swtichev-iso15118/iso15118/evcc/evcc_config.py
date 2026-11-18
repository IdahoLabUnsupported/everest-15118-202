# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
# This file has been modified from the original.

import json
import logging
from typing import Any, Dict, List, Optional

from aiofile import async_open
from pydantic import BaseModel, Field, validator

from iso15118.shared.messages.enums import (
    UINT_16_MAX,
    EnergyTransferModeEnum,
    Protocol,
    ServiceV20,
)
from iso15118.shared.utils import (
    load_requested_energy_services,
    load_requested_protocols,
)

logger = logging.getLogger(__name__)


class EVCCConfig(BaseModel):
    _default_protocols = [
        "ISO_15118_2",
        "DIN_SPEC_70121",
        "ISO_15118_20_AC",
        "ISO_15118_20_DC",
    ]
    _default_supported_energy_services = ["AC"]
    raw_supported_energy_services: List[str] = Field(
        _default_supported_energy_services, max_items=4, alias="supportedEnergyServices"
    )
    supported_energy_services: List[ServiceV20] = None
    is_cert_install_needed: bool = Field(False, alias="isCertInstallNeeded")
    # Indicates the security level (either TCP (unencrypted) or TLS (encrypted))
    # the EVCC shall send in the SDP request
    use_tls: Optional[bool] = Field(True, alias="useTls")
    # How often shall SDP (SECC Discovery Protocol) retries happen before reverting
    # to using nominal duty cycle PWM-based charging?
    sdp_retry_cycles: Optional[int] = Field(1, alias="sdpRetryCycles")
    # How often shall ESDP (Extended SECC Discovery Protocol) retry cycles happen
    # before falling back to regular SDP?
    esdp_retry_cycles: Optional[int] = Field(35, alias="esdpRetryCycles")
    # For ISO 15118-20 only
    # Maximum amount of contract certificates (and associated certificate chains)
    # the EV can store. That value is used in the CertificateInstallationReq.
    # Must be an integer between 0 and 65535, should be bigger than 0.
    max_contract_certs: Optional[int] = Field(3, alias="maxContractCerts")
    # Indicates whether or not the EVCC should always enforce a TLS-secured
    # communication session.
    # If True, the EVCC will only continue setting up a communication session if
    # the SECC's SDP response has the Security field set
    # to the enum value Security.TLS.
    # If the USE_TLS setting is set to False and ENFORCE_TLS is set to True, then
    # ENFORCE_TLS overrules USE_TLS.
    enforce_tls: bool = Field(False, alias="enforceTls")
    # Supported protocols, used for SupportedAppProtocol (SAP). The order in which
    # the protocols are listed here determines the priority (i.e. first list entry
    # the protocols are listed here determines the priority (i.e. first list entry
    # has higher priority than second list entry). A list entry must be a member
    # of the Protocol enum
    raw_supported_protocols: Optional[List[str]] = Field(
        _default_protocols, max_items=6, alias="supportedProtocols"
    )
    supported_protocols: Optional[List[Protocol]] = None
    energy_transfer_mode: Optional[EnergyTransferModeEnum] = Field(
        EnergyTransferModeEnum.AC_THREE_PHASE_CORE, alias="energyTransferMode"
    )
    # Indicates the maximum number of entries the EVCC supports within the
    # sub-elements of a ScheduleTuple (e.g. PowerScheduleType and PriceRuleType in
    # ISO 15118-20 as well as PMaxSchedule and SalesTariff in ISO 15118-2).
    # The SECC must not transmit more entries than defined in this parameter.
    max_supporting_points: Optional[int] = Field(1024, alias="maxSupportingPoints")

    # charge cycle count
    charge_loop_cycle: Optional[int] = Field(10, alias="chargeLoopCycle")
    # Charging interface type per IEC 62196 designation [V2G202-0064].
    # Valid values: iec-62196-2-type-1, iec-62196-2-type-2, iec-62196-2-type-4,
    #   iec-62196-3-aa (CHAdeMO), iec-62196-3-bb (GB/T), iec-62196-3-ee (CCS1),
    #   iec-62196-3-ff (CCS2), iec-62196-3-gg (ChaoJi), iec-62196-3-jj (Ultra ChaoJi),
    #   iec-62196-3-hh (MCS), sae-j3400 (NACS)
    charging_interface: Optional[str] = Field("iec-62196-3-ee", alias="chargingInterface")
    # Whether the EV has a socket/inlet or a connector/plug [V2G202-0066].
    # Valid values: socket-inlet, connector-plug
    interface_type: Optional[str] = Field("connector-plug", alias="interfaceType")

    # ElectricalChargingSystem editions advertised in the ESDPReq
    # ElectricalChargingSystemExtension per ISO/PAS 15118-202:2025 §6.5.3 Tables 9-10
    # [V2G202-0054, 0067-0068]. Empty list ⇒ encoder advertises every value defined in
    # Table 10. Valid values: iec61851-1-ed2, iec61851-1-ed3, iec61851-1-ed4,
    # iec61851-23-ed1, iec61851-23-ed2, iec61851-23-ed3, iec61851-23-3-ed1,
    # sae-j1772-201602, sae-j1772-201710, sae-j1772-202401, sae-j3068-202207,
    # sae-j3068-202409, sae-j3400-202409.
    electrical_charging_systems: Optional[List[str]] = Field(
        default_factory=list, alias="electricalChargingSystems"
    )

    # Optional ControlPilotBCBToggleSupport values per Table 11 [V2G202-0069, 0070].
    # Valid values: slacValidation, wakeup. Empty list ⇒ optional field omitted.
    control_pilot_bcb_toggle_support: Optional[List[str]] = Field(
        default_factory=list, alias="controlPilotBcbToggleSupport"
    )

    # Maximum contactor temperature in °C advertised in ESDPReq
    # ConductiveChargingInterfaceLimitations [V2G202-0103]. Per the standard this is
    # the EV's contactor hardware rating at the vehicle inlet/connector, sourced from
    # hardware spec — not an arbitrary placeholder. Typical values 80–105 °C.
    max_contactor_celsius_temperature: Optional[int] = Field(
        80, alias="maxContactorCelsiusTemperature"
    )

    # ACChargingParametersExtension values advertised when AC charging is supported
    # [V2G202-0098..0101]. nominal voltage is the single-phase value.
    ac_nominal_voltages: Optional[List[int]] = Field(
        default_factory=lambda: [230], alias="acNominalVoltages"
    )
    ac_number_of_phases: Optional[int] = Field(3, alias="acNumberOfPhases")
    ac_grid_frequencies: Optional[List[int]] = Field(
        default_factory=lambda: [50], alias="acGridFrequencies"
    )

    # EVCharacteristicsExtension values advertised in ESDPReq [V2G202-0105..0110].
    # VIS is optional and defaults to omitted because it must not identify a specific EV.
    ev_world_manufacturer_identifier: Optional[str] = Field(
        "1HG", alias="evWorldManufacturerIdentifier"
    )
    ev_vehicle_descriptor_section: Optional[str] = Field(
        None, alias="evVehicleDescriptorSection"
    )
    ev_vehicle_indicator_section: Optional[str] = Field(
        None, alias="evVehicleIndicatorSection"
    )
    evcc_software_version: Optional[str] = Field(
        None, alias="evccSoftwareVersion"
    )
    # EMSPInfoExtension values advertised in ESDPReq [V2G202-0094..0097].
    # Example:
    # [{"emspIdentifiers": ["USINL"], "authorizationMethods": ["pnc-2"]}]
    emsp_info: Optional[List[Dict[str, List[str]]]] = Field(
        default_factory=list, alias="emspInfo"
    )

    def load_raw_values(self):
        # conversion of list of strings to enum types.
        self.supported_energy_services = load_requested_energy_services(
            self.raw_supported_energy_services
        )
        self.supported_protocols = load_requested_protocols(
            self.raw_supported_protocols
        )

    @validator("max_supporting_points", pre=True, always=True)
    def check_max_supporting_points(cls, value):
        if not 0 <= value <= 1024:
            raise ValueError(
                "Wrong range for max_supporting_points in config file. "
                "Should be in [0..1024]"
            )
        return value

    @validator("sdp_retry_cycles", pre=True, always=True)
    def check_sdp_retry_cycle(cls, value):
        if value < 0:
            raise ValueError(
                "Wrong range for sdp_retry_cycles in config file. " "Should be in [0..]"
            )
        return value

    @validator("esdp_retry_cycles", pre=True, always=True)
    def check_esdp_retry_cycle(cls, value):
        if value < 0:
            raise ValueError(
                "Wrong range for esdp_retry_cycles in config file. "
                "Should be in [0..]"
            )
        return value

    @validator("max_contract_certs", pre=True, always=True)
    def check_max_contract_certs(cls, value):
        if not 1 < value < UINT_16_MAX:
            raise ValueError(
                "Wrong range for max_contract_certs in config file. "
                "Should be in [1..UINT_16_MAX]"
            )
        return value

    @validator("ac_nominal_voltages", each_item=True)
    def check_ac_nominal_voltage(cls, value):
        if not 0 <= value <= 65535:
            raise ValueError(
                "Wrong range for ac_nominal_voltages in config file. "
                "Should be in [0..65535]"
            )
        return value

    @validator("ac_number_of_phases", pre=True, always=True)
    def check_ac_number_of_phases(cls, value):
        if value is None:
            return 3
        if not 0 <= value <= 255:
            raise ValueError(
                "Wrong range for ac_number_of_phases in config file. "
                "Should be in [0..255]"
            )
        return value

    @validator("ac_grid_frequencies", each_item=True)
    def check_ac_grid_frequency(cls, value):
        if not 0 <= value <= 255:
            raise ValueError(
                "Wrong range for ac_grid_frequencies in config file. "
                "Should be in [0..255]"
            )
        return value

    @validator("ev_world_manufacturer_identifier", pre=True, always=True)
    def check_ev_world_manufacturer_identifier(cls, value):
        if value is None:
            raise ValueError(
                "ev_world_manufacturer_identifier is required and must be exactly 3 characters"
            )
        value = str(value)
        if len(value) != 3:
            raise ValueError(
                "Wrong length for ev_world_manufacturer_identifier in config file. "
                "Should be exactly 3 characters"
            )
        return value

    @validator(
        "ev_vehicle_descriptor_section",
        "ev_vehicle_indicator_section",
        "evcc_software_version",
        pre=True,
        always=True,
    )
    def normalize_optional_ev_characteristics_string(cls, value):
        if value is None:
            return None
        value = str(value)
        return value or None

    @validator("charging_interface")
    def check_charging_interface(cls, value):
        return cls._check_esdp_enum_value(
            value,
            "ChargingInterface",
            "charging_interface",
        )

    @validator("interface_type")
    def check_interface_type(cls, value):
        return cls._check_esdp_enum_value(
            value,
            "InterfaceType",
            "interface_type",
        )

    @validator("electrical_charging_systems", each_item=True)
    def check_electrical_charging_system(cls, value):
        return cls._check_esdp_enum_value(
            value,
            "ElectricalChargingSystem",
            "electrical_charging_systems",
        )

    @validator("control_pilot_bcb_toggle_support", each_item=True)
    def check_control_pilot_bcb_toggle_support(cls, value):
        return cls._check_esdp_enum_value(
            value,
            "ControlPilotBCBToggleSupport",
            "control_pilot_bcb_toggle_support",
        )

    @validator("emsp_info", pre=True, always=True)
    def normalize_emsp_info(cls, value):
        if not value:
            return []
        if not isinstance(value, list):
            raise ValueError("emspInfo must be a list")

        normalized = []
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                raise ValueError(f"emspInfo[{index}] must be an object")

            identifiers = cls._non_empty_string_list(
                item.get("emspIdentifiers"), f"emspInfo[{index}].emspIdentifiers"
            )
            authorization_methods = cls._non_empty_string_list(
                item.get("authorizationMethods"),
                f"emspInfo[{index}].authorizationMethods",
            )
            from iso15118.evcc.asn1.esdp_asn1_main import (
                get_authorization_method_names,
            )

            valid_authorization_methods = get_authorization_method_names()
            for method in authorization_methods:
                if method not in valid_authorization_methods:
                    valid_methods = ", ".join(sorted(valid_authorization_methods))
                    raise ValueError(
                        f"Invalid EMSP authorization method '{method}'. "
                        f"Expected one of {valid_methods}"
                    )

            normalized.append(
                {
                    "emspIdentifiers": identifiers,
                    "authorizationMethods": authorization_methods,
                }
            )
        return normalized

    @staticmethod
    def _non_empty_string_list(value: Any, field_name: str) -> List[str]:
        if not isinstance(value, list) or not value:
            raise ValueError(f"{field_name} must be a non-empty list")
        result = []
        for item in value:
            item = str(item)
            if not item:
                raise ValueError(f"{field_name} entries must be non-empty strings")
            result.append(item)
        return result

    @staticmethod
    def _check_esdp_enum_value(value: Any, enum_name: str, field_name: str) -> str:
        value = str(value)
        from iso15118.evcc.asn1.esdp_asn1_main import get_enum_names

        valid_values = get_enum_names(enum_name)
        if value not in valid_values:
            raise ValueError(
                f"Invalid ESDP {field_name} '{value}'. "
                f"Expected one of {', '.join(sorted(valid_values))}"
            )
        return value


async def load_from_file(file_name: str) -> EVCCConfig:
    try:
        async with async_open(file_name, "r") as f:
            json_content = await f.read()
            data = json.loads(json_content)
            ev_config = EVCCConfig(**data)
            ev_config.load_raw_values()
            logger.info("EVCC Settings")
            for key, value in ev_config.dict().items():
                if not key.startswith("raw"):
                    logger.info(f"{key:30}: {value}")
        return ev_config
    except Exception as err:
        logger.debug(f"Error on loading evcc config file:{err}")
    return EVCCConfig()

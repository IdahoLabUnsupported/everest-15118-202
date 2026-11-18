# Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

import os
import hashlib
import logging
import re
import asn1tools
from asn1tools.codecs import constraints_checker, oer, type_checker
from asn1tools.compiler import Specification

from iso15118.shared.security import CertPath
from iso15118.shared.settings import get_PKI_PATH

logger = logging.getLogger(__name__)

# Extension UUIDs per Table 5 of ISO/PAS 15118-202:2025
# Extension UUIDs are still manual constants. The local ASN.1 file explicitly keeps
# extensionID as a raw OCTET STRING and omits the upstream extension object set, 
# so those UUID values are not present to extract from the current schema.
_UUID_CHARGING_INTERFACE      = bytes.fromhex('3EAE3DCBE9554A1D84C6B4EEF86460F3')
_UUID_ELECTRICAL_CHARGING_SYS = bytes.fromhex('25992AFF1A58455FAFFDE58EB6F32600')
_UUID_IPV6_SOCKET             = bytes.fromhex('A2398E1B3C79495D9CE1BD108DEC564E')
_UUID_TLS12_INFO              = bytes.fromhex('7C704049C4DD4353967EDAF21C9D453A')
_UUID_CHARGING_SERVICE        = bytes.fromhex('FAE82704EEBA4892ABCCFE8093B86312')
_UUID_EMSP_INFO               = bytes.fromhex('AFF57F501E6E4868910C4D76BF35296B')
_UUID_AC_CHARGING_PARAMETERS  = bytes.fromhex('F7F4265C3844447C8D7FBB3857A9B6AB')
_UUID_CONDUCTIVE_LIMITS       = bytes.fromhex('27D71E41EA8C4FB2BA431E1E7E60E360')
_UUID_EV_CHARACTERISTICS      = bytes.fromhex('5FD6334458DC4173B92608F63117D411')
_UUID_EVSE_CHARACTERISTICS    = bytes.fromhex('F0E77C3ADC41477398C9F177F44775BB')


class _COERCompiler(oer.Compiler):
    """OER compiler that always length-prefixes UTF8String values.

    asn1tools (0.167.0) models UTF8String as a known-multiplier character string
    and drops the length determinant when its SIZE constraint is fixed. ITU-T
    X.696 clause 27 reserves that form for IA5String, NumericString,
    PrintableString and VisibleString; a UTF8String is always length-prefixed.
    The only fixed-size UTF8String in the schema is
    worldManufacturerIdentifier UTF8String (SIZE (3)), which must go on the wire
    as 0x03 followed by the three WMI bytes.
    """

    def compile_type(self, name, type_descriptor, module_name):
        compiled = super().compile_type(name, type_descriptor, module_name)
        if isinstance(compiled, oer.UTF8String):
            compiled.number_of_bytes = None
        return compiled


def _compile_coer(parsed):
    """Mirror asn1tools.compile_dict(parsed, 'oer') using _COERCompiler."""
    return Specification(
        _COERCompiler(parsed).process(),
        oer.decode_full_length,
        type_checker.compile_dict(parsed),
        constraints_checker.compile_dict(parsed),
    )


_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'esdp_definitions.asn')
_parsed_schema = asn1tools.parse_files(_SCHEMA_PATH)
_schema = _compile_coer(_parsed_schema)

_ENUM_BLOCK_RE_TEMPLATE = r'\b{}\s*::=\s*ENUMERATED\s*\{{(?P<body>.*?)\n\}}'
_ENUM_MEMBER_RE = re.compile(
    r'^\s*(?P<name>[A-Za-z][A-Za-z0-9-]*)'
    r'(?:\s*\(\s*(?P<value>-?\d+)\s*\))?',
)


def _asn1_modules():
    if isinstance(_parsed_schema, dict) and 'modules' in _parsed_schema:
        return _parsed_schema['modules']
    return _parsed_schema


def _extract_enum_values_from_asn1tools(type_name):
    modules = _asn1_modules()
    if not isinstance(modules, dict):
        return None

    for module in modules.values():
        if not isinstance(module, dict):
            continue
        type_def = module.get('types', {}).get(type_name)
        if not isinstance(type_def, dict):
            continue

        values = type_def.get('values') or type_def.get('members')
        if not values:
            continue

        enum_values = {}
        next_auto_value = 0
        value_items = values.items() if isinstance(values, dict) else values
        for item in value_items:
            # asn1tools represents an ASN.1 extension marker (``...``) as
            # ``None`` in an ENUMERATED value list. It is not an enum member
            # and must not consume an automatically assigned numeric value.
            if item is None:
                continue
            if isinstance(item, str):
                name, value = item, next_auto_value
            elif isinstance(item, (tuple, list)) and item:
                name = item[0]
                value = (
                    item[1]
                    if len(item) > 1 and item[1] is not None
                    else next_auto_value
                )
            else:
                # The parsed schema structure is owned by asn1tools and may
                # vary between releases. Let the caller use the ASN.1 text
                # parser rather than failing module import on an unfamiliar
                # representation.
                return None
            if not isinstance(name, str):
                return None
            try:
                numeric_value = int(value)
            except (TypeError, ValueError):
                return None
            enum_values[name] = numeric_value
            next_auto_value = numeric_value + 1
        return enum_values or None

    return None


def _extract_enum_values_from_asn_text(type_name):
    with open(_SCHEMA_PATH, 'r') as schema_file:
        schema_text = schema_file.read()

    enum_block_re = re.compile(
        _ENUM_BLOCK_RE_TEMPLATE.format(re.escape(type_name)),
        re.MULTILINE | re.DOTALL,
    )
    match = enum_block_re.search(schema_text)
    if not match:
        raise ValueError(f'ASN.1 enum {type_name} was not found in {_SCHEMA_PATH}')

    enum_values = {}
    next_auto_value = 0
    for line in match.group('body').splitlines():
        line = line.split('--', 1)[0].strip().rstrip(',')
        if not line or line == '...':
            continue
        member = _ENUM_MEMBER_RE.match(line)
        if not member:
            continue
        name = member.group('name')
        value = (
            int(member.group('value'))
            if member.group('value') is not None
            else next_auto_value
        )
        enum_values[name] = value
        next_auto_value = value + 1

    if not enum_values:
        raise ValueError(f'ASN.1 enum {type_name} did not contain any values')
    return enum_values


def _enum_values(type_name):
    return (
        _extract_enum_values_from_asn1tools(type_name)
        or _extract_enum_values_from_asn_text(type_name)
    )


def _enum_names(type_name):
    return frozenset(_enum_values(type_name))


def get_enum_names(type_name):
    return _enum_names(type_name)


def get_authorization_method_names():
    return get_enum_names('AuthorizationMethod')


def get_electrical_charging_system_names():
    return get_enum_names('ElectricalChargingSystem')


SECURITY_PROFILE_NAME_TO_INT = _enum_values('SecurityProfile')
SECURITY_PROFILE_TCP_ONLY = SECURITY_PROFILE_NAME_TO_INT['tcpOnly']
SECURITY_PROFILE_ISO_15118_2_2014 = SECURITY_PROFILE_NAME_TO_INT['iso-15118-2-2014']
SECURITY_PROFILE_ISO_15118_2_2026 = SECURITY_PROFILE_NAME_TO_INT['iso-15118-2-2026']
SECURITY_PROFILE_ISO_15118_20_2022 = SECURITY_PROFILE_NAME_TO_INT['iso-15118-20-2022']

# SecurityProfile values per ISO/PAS 15118-202:2025 Table 17.
_SECURITY_INT_TO_STR = {
    value: name for name, value in SECURITY_PROFILE_NAME_TO_INT.items()
}

_ALL_ELECTRICAL_CHARGING_SYSTEMS = tuple(_enum_values('ElectricalChargingSystem'))

_TLS12_INFO_SECURITY_PROFILES = {'iso-15118-2-2014', 'iso-15118-2-2026'}


def _validated_int_list(name, values, min_value, max_value):
    result = [int(value) for value in values]
    if not result:
        raise ValueError(f'{name} must contain at least one value')
    for value in result:
        if value < min_value or value > max_value:
            raise ValueError(f'{name} entries must be in [{min_value}..{max_value}]')
    return result


def _validated_int(name, value, min_value, max_value):
    int_value = int(value)
    if int_value < min_value or int_value > max_value:
        raise ValueError(f'{name} must be in [{min_value}..{max_value}]')
    return int_value


def _security_profile_name(security):
    security_value = int(security)
    try:
        return _SECURITY_INT_TO_STR[security_value]
    except KeyError as exc:
        valid_values = ', '.join(str(value) for value in sorted(_SECURITY_INT_TO_STR))
        raise ValueError(
            f'Unsupported SecurityProfile value {security_value}; expected one of '
            f'{valid_values} per ISO/PAS 15118-202:2025 Table 17'
        ) from exc


def _security_profile_names(security_profiles):
    if isinstance(security_profiles, (str, bytes)):
        profile_values = [security_profiles]
    else:
        try:
            profile_values = list(security_profiles)
        except TypeError:
            profile_values = [security_profiles]

    profile_names = []
    for profile in profile_values:
        profile_name = (
            profile
            if isinstance(profile, str)
            else _security_profile_name(profile)
        )
        if profile_name not in _SECURITY_INT_TO_STR.values():
            valid_names = ', '.join(_SECURITY_INT_TO_STR.values())
            raise ValueError(
                f'Unsupported SecurityProfile value {profile_name}; '
                f'expected one of {valid_names}'
            )
        if profile_name not in profile_names:
            profile_names.append(profile_name)

    if not profile_names:
        raise ValueError('At least one SecurityProfile must be advertised')
    return profile_names


def _security_profile_tuples(profile_names, energy_transfer_modes):
    return [
        {
            'securityProfile': profile_name,
            'authorizationMethodList': ['eim'],
            'energyTransferModeTupleList': energy_transfer_modes,
        }
        for profile_name in profile_names
    ]


def _energy_transfer_mode_tuples(supports_dc_charging, supports_ac_charging):
    modes = []
    if supports_dc_charging:
        modes.append({'energyTransferMode': 'dc', 'controlMode': 'ev-spontaneous'})
    if supports_ac_charging:
        modes.append({'energyTransferMode': 'ac', 'controlMode': 'ev-spontaneous'})
    if not modes:
        raise ValueError('At least one of supports_dc_charging/supports_ac_charging must be true')
    return modes


def _load_v2g_root_cert_sha1_hashes():
    """Return RFC 6066 cert_sha1_hash values for EVCC-trusted V2G roots."""
    cert_path = os.path.join(get_PKI_PATH(), CertPath.V2G_ROOT_DER)
    with open(cert_path, 'rb') as cert_file:
        cert_der = cert_file.read()
    if not cert_der:
        raise ValueError(f'V2G root certificate is empty: {cert_path}')
    return [hashlib.sha1(cert_der).digest()]


def _optional_non_empty_string(value):
    if value is None:
        return None
    value = str(value)
    return value or None


def _non_empty_string_list(name, values):
    result = [str(value) for value in values]
    if not result:
        raise ValueError(f'{name} must contain at least one value')
    for value in result:
        if not value:
            raise ValueError(f'{name} entries must be non-empty strings')
    return result


def _emsp_info_tuples(emsp_info):
    if not emsp_info:
        return []

    tuples = []
    for index, item in enumerate(emsp_info):
        emsp_identifiers = _non_empty_string_list(
            f'emsp_info[{index}].emspIdentifiers',
            item.get('emspIdentifiers', []),
        )
        authorization_methods = _non_empty_string_list(
            f'emsp_info[{index}].authorizationMethods',
            item.get('authorizationMethods', []),
        )
        tuples.append({
            'emspIdentifiersList': emsp_identifiers,
            'authorizationMethodsList': authorization_methods,
        })
    return tuples


def encode_data(security_profiles, charging_interface: str = 'iec-62196-3-ee',
                interface_type: str = 'connector-plug',
                electrical_charging_systems=None,
                control_pilot_bcb_toggle_support=None,
                max_contactor_celsius_temperature: int = 80,
                tls12_ca_root_key_identifiers=None,
                supports_dc_charging: bool = True,
                supports_ac_charging: bool = True,
                ac_nominal_voltages=None,
                ac_number_of_phases: int = 3,
                ac_grid_frequencies=None,
                ev_world_manufacturer_identifier: str = '1HG',
                ev_vehicle_descriptor_section=None,
                ev_vehicle_indicator_section=None,
                evcc_software_version=None,
                emsp_info=None):
    """Encode ESDP extensions using CANONICAL-OER (X.696, ISO/IEC 8825-7).

    Args:
        security_profiles: SecurityProfile value(s) per ISO/PAS 15118-202:2025 Table 17
            (0=tcpOnly, 10=iso-15118-2-2014, 11=iso-15118-2-2026,
            20=iso-15118-20-2022)
        charging_interface: IEC 62196 connector designation (e.g. 'iec-62196-3-ee')
        interface_type: 'socket-inlet' or 'connector-plug'
        electrical_charging_systems: list of ElectricalChargingSystem enum names per
            ISO/PAS 15118-202:2025 Table 10. None or empty falls back to advertising
            every value defined in Table 10.
        control_pilot_bcb_toggle_support: optional list of ControlPilotBCBToggleSupport
            enum names per Table 11. None or empty omits the optional field.
        tls12_ca_root_key_identifiers: optional iterable of 20-byte RFC 6066 cert_sha1_hash
            values. If omitted while using an ISO 15118-2 TLS profile, the configured V2G
            root DER certificate is loaded from the Josev PKI path and hashed.
        supports_dc_charging: True if the EV can use DC charging in this ESDP session.
        supports_ac_charging: True if the EV can use AC charging in this ESDP session.
        ac_nominal_voltages: AC single-phase nominal voltages in volts for
            ACChargingParametersExtension. Defaults to [230] when AC is supported.
        ac_number_of_phases: maximum number of AC phases supported.
        ac_grid_frequencies: supported AC grid frequencies in Hz. Defaults to [50]
            when AC is supported.
        ev_world_manufacturer_identifier: mandatory ISO 3779 WMI for
            EVCharacteristics. Must be exactly 3 characters.
        ev_vehicle_descriptor_section: optional ISO 3779 VDS. Omitted when empty.
        ev_vehicle_indicator_section: optional ISO 3779 VIS. Omitted when empty;
            if provided, it must not identify a specific EV [V2G202-0110].
        evcc_software_version: optional EVCC software version. Omitted when empty.
        emsp_info: optional EMSPInfoExtension tuples. Each tuple contains
            emspIdentifiers and authorizationMethods lists.

    Returns:
        Tuple of (encoded_bytes, byte_count)
    """
    security_profile_names = _security_profile_names(security_profiles)
    energy_transfer_modes = _energy_transfer_mode_tuples(
        supports_dc_charging, supports_ac_charging,
    )

    ci_encoded = _schema.encode('ChargingInterfaceExtension', {
        'chargingInterface': charging_interface,
        'interfaceType': interface_type,
    })

    ecs_payload = {
        'electricalChargingSystemsList': list(electrical_charging_systems)
            if electrical_charging_systems else list(_ALL_ELECTRICAL_CHARGING_SYSTEMS),
    }
    if control_pilot_bcb_toggle_support:
        ecs_payload['controlPilotBCBToggleSupport'] = list(control_pilot_bcb_toggle_support)
    bs_encoded = _schema.encode('ElectricalChargingSystemExtension', ecs_payload)

    tls12_info_encoded = None
    if any(
        profile_name in _TLS12_INFO_SECURITY_PROFILES
        for profile_name in security_profile_names
    ):
        ca_root_hashes = (
            list(tls12_ca_root_key_identifiers)
            if tls12_ca_root_key_identifiers is not None
            else _load_v2g_root_cert_sha1_hashes()
        )
        for ca_root_hash in ca_root_hashes:
            if len(ca_root_hash) != 20:
                raise ValueError('TLS12Info caRootKeyIdentifiersList entries must be exactly 20 bytes')
        tls12_info_encoded = _schema.encode('TLS12InfoExtension', {
            'caRootKeyIdentifiersList': [bytes(ca_root_hash) for ca_root_hash in ca_root_hashes],
        })

    charging_service_tuples = []
    if supports_dc_charging:
        charging_service_tuples.append({
            'hlcProtocol': 'din-spec-70121-2014',
            'securityProfileTupleList': [
                {
                    'securityProfile': 'tcpOnly',
                    'authorizationMethodList': ['eim'],
                    'energyTransferModeTupleList': [
                        {'energyTransferMode': 'dc', 'controlMode': 'ev-spontaneous'},
                    ],
                },
            ],
        })
    iso_15118_2_profiles = [
        profile_name for profile_name in security_profile_names
        if profile_name in {
            'tcpOnly',
            'iso-15118-2-2014',
        }
    ]
    if iso_15118_2_profiles:
        charging_service_tuples.append({
            'hlcProtocol': 'iso-15118-2-2014',
            'securityProfileTupleList': _security_profile_tuples(
                iso_15118_2_profiles, energy_transfer_modes,
            ),
        })

    iso_15118_2_2026_profiles = [
        profile_name for profile_name in security_profile_names
        if profile_name == 'iso-15118-2-2026'
    ]
    if iso_15118_2_2026_profiles:
        charging_service_tuples.append({
            'hlcProtocol': 'iso-15118-2-2026',
            'securityProfileTupleList': _security_profile_tuples(
                iso_15118_2_2026_profiles, energy_transfer_modes,
            ),
        })

    iso_15118_20_profiles = [
        profile_name for profile_name in security_profile_names
        if profile_name == 'iso-15118-20-2022'
    ]
    if iso_15118_20_profiles:
        charging_service_tuples.append({
            'hlcProtocol': 'iso-15118-20-2022',
            'securityProfileTupleList': _security_profile_tuples(
                iso_15118_20_profiles, energy_transfer_modes,
            ),
        })

    if not charging_service_tuples:
        raise ValueError('At least one ChargingServiceTuple must be advertised')

    # ChargingServiceExtension [V2G202-0084..0093] per §6.5.6 Tables 14-20.
    # Same restructure as SECC side: wrapper + field renames + per-mode controlMode.
    # ControlMode 'ev-spontaneous' matches existing ISO 15118-2 semantics.
    hlc_encoded = _schema.encode('ChargingServiceExtension', {
        'chargingServiceTuplesList': charging_service_tuples,
    })

    emsp_info_encoded = None
    emsp_tuples = _emsp_info_tuples(emsp_info)
    if emsp_tuples:
        emsp_info_encoded = _schema.encode('EMSPInfoExtension', {
            'emspIdentifiersTuplesList': emsp_tuples,
        })

    ac_charging_params_encoded = None
    if supports_ac_charging:
        ac_charging_params_encoded = _schema.encode('ACChargingParametersExtension', {
            'nominalVoltageList': _validated_int_list(
                'ac_nominal_voltages', ac_nominal_voltages or [230], 0, 65535,
            ),
            'gridFrequencyList': _validated_int_list(
                'ac_grid_frequencies', ac_grid_frequencies or [50], 0, 255,
            ),
            'numberOfPhases': _validated_int('ac_number_of_phases', ac_number_of_phases, 0, 255),
        })

    # ConductiveChargingInterfaceLimitations [V2G202-0102/0103]. Per the standard the
    # temperature value is the EV's contactor hardware rating, sourced from config.
    cond_limits_encoded = _schema.encode('ConductiveChargingInterfaceLimitationsExtension', {
        'maximumContactorCelsiusTemperature': int(max_contactor_celsius_temperature),
    })

    world_manufacturer_identifier = str(ev_world_manufacturer_identifier)
    if len(world_manufacturer_identifier) != 3:
        raise ValueError('EVCharacteristics worldManufacturerIdentifier must be exactly 3 characters')

    ev_chars_payload = {
        'worldManufacturerIdentifier': world_manufacturer_identifier,
    }
    vehicle_descriptor_section = _optional_non_empty_string(ev_vehicle_descriptor_section)
    vehicle_indicator_section = _optional_non_empty_string(ev_vehicle_indicator_section)
    evcc_software_version = _optional_non_empty_string(evcc_software_version)
    if vehicle_descriptor_section is not None:
        ev_chars_payload['vehicleDescriptorSection'] = vehicle_descriptor_section
    if vehicle_indicator_section is not None:
        logger.warning(
            'EVCharacteristics vehicleIndicatorSection is configured; ensure it does '
            'not identify a specific EV per V2G202-0110'
        )
        ev_chars_payload['vehicleIndicatorSection'] = vehicle_indicator_section
    if evcc_software_version is not None:
        ev_chars_payload['evccSoftwareVersion'] = evcc_software_version

    ev_chars_encoded = _schema.encode('EVCharacteristicsExtension', ev_chars_payload)

    # ESDPReq send-rule audit:
    # - EVCC includes EVCharacteristics in ESDPReq per [V2G202-0105].
    # - EVCC intentionally omits IPv6SocketExtension per [V2G202-0072].
    #   IPv6SocketExtension is decoded from ESDPRes only.
    extension_items = [
        {'extensionID': _UUID_CHARGING_INTERFACE,      'extensionValue': ci_encoded},
        {'extensionID': _UUID_ELECTRICAL_CHARGING_SYS, 'extensionValue': bs_encoded},
    ]
    if tls12_info_encoded is not None:
        extension_items.append({'extensionID': _UUID_TLS12_INFO, 'extensionValue': tls12_info_encoded})
    extension_items.append({'extensionID': _UUID_CHARGING_SERVICE, 'extensionValue': hlc_encoded})
    if emsp_info_encoded is not None:
        extension_items.append({'extensionID': _UUID_EMSP_INFO, 'extensionValue': emsp_info_encoded})
    if ac_charging_params_encoded is not None:
        extension_items.append({
            'extensionID': _UUID_AC_CHARGING_PARAMETERS,
            'extensionValue': ac_charging_params_encoded,
        })
    extension_items.extend([
        {'extensionID': _UUID_CONDUCTIVE_LIMITS,  'extensionValue': cond_limits_encoded},
        {'extensionID': _UUID_EV_CHARACTERISTICS, 'extensionValue': ev_chars_encoded},
    ])

    extensions_data = {'esdpExtensionsList': extension_items}

    bin_rep = _schema.encode('ESDPExtensions', extensions_data)
    logger.info(f'ESDP extensions encoded: {len(bin_rep)} bytes')

    return bin_rep, len(bin_rep)


def decode_data(esdp_extensions):
    """Decode CANONICAL-OER encoded ESDP extensions.

    Extracts the IPv6 address and TCP port from the IPv6SocketExtension and
    the security profile from the ChargingService extension.

    Returns:
        [port_int, ipv6_bytes, security_str]. port_int is now a Python int
        (schema change in -202: tcpPort INTEGER (1..65535), was OCTET STRING).
        security_str defaults to 'tcpOnly' unless a TLS profile is offered.
    """
    prt = None
    ipv6addr = None
    sec = 'tcpOnly'
    offered_security_profiles = set()
    preferred_security_profiles = (
        'iso-15118-20-2022',
        'iso-15118-2-2026',
        'iso-15118-2-2014',
        'tcpOnly',
    )

    decoded = _schema.decode('ESDPExtensions', esdp_extensions)

    for ext in decoded.get('esdpExtensionsList', []):
        ext_id = ext['extensionID']
        ext_val = ext['extensionValue']

        if ext_id == _UUID_CHARGING_INTERFACE:
            ci_ext = _schema.decode('ChargingInterfaceExtension', ext_val)
            logger.info(
                'ChargingInterfaceExtension: chargingInterface=%s interfaceType=%s',
                ci_ext['chargingInterface'], ci_ext['interfaceType'],
            )

        elif ext_id == _UUID_ELECTRICAL_CHARGING_SYS:
            ecs_ext = _schema.decode('ElectricalChargingSystemExtension', ext_val)
            logger.info(
                'ElectricalChargingSystemExtension: systems=%s bcbToggles=%s',
                ecs_ext.get('electricalChargingSystemsList'),
                ecs_ext.get('controlPilotBCBToggleSupport'),
            )

        elif ext_id == _UUID_IPV6_SOCKET:
            # IPv6SocketExtension [V2G202-0071..0077] per §6.5.4 Table 12.
            # New shape: wrapper SEQUENCE around a list of IPv6SocketTuple, each carrying
            # ipv6Address (bytes), tcpPort (int — was OCTET STRING), securityProfileList.
            # The SECC may advertise multiple tuples; pick the first one whose advertised
            # securityProfileList contains the EVCC's preferred profile. Preference order
            # (high to low): iso-15118-20-2022, iso-15118-2-2026, iso-15118-2-2014, tcpOnly.
            # Real runtime support for the top two is gated on Item 6 (ChargingService
            # restructure + TLS handshake updates) — for now they're recognised but the
            # downstream pipeline will still negotiate iso-15118-2-2014 or tcpOnly.
            ipv6_ext = _schema.decode('IPv6SocketExtension', ext_val)
            tuples = ipv6_ext.get('ipv6SocketTuplesList', [])
            chosen = None
            for preferred in ('iso-15118-20-2022', 'iso-15118-2-2026', 'iso-15118-2-2014', 'tcpOnly'):
                chosen = next(
                    (t for t in tuples if preferred in t.get('securityProfileList', [])),
                    None,
                )
                if chosen is not None:
                    break
            if chosen is None and tuples:
                chosen = tuples[0]  # fallback: first tuple regardless of profile
            if chosen is not None:
                ipv6addr = chosen['ipv6Address']
                prt = chosen['tcpPort']
                offered_security_profiles.update(
                    chosen.get('securityProfileList', [])
                )
                logger.info(
                    'IPv6SocketTuple selected: tcpPort=%d securityProfiles=%s (of %d tuple(s))',
                    prt, chosen.get('securityProfileList'), len(tuples),
                )

        elif ext_id == _UUID_TLS12_INFO:
            tls12_info = _schema.decode('TLS12InfoExtension', ext_val)
            hashes = tls12_info.get('caRootKeyIdentifiersList', [])
            logger.info(
                'TLS12InfoExtension: caRootKeyIdentifiers=%s',
                [ca_hash.hex() for ca_hash in hashes],
            )

        elif ext_id == _UUID_EMSP_INFO:
            # EMSPInfoExtension [V2G202-0094..0097] per §6.5.7 Table 21.
            # Each tuple binds a set of EMSP identifiers (UTF8String) to the authorization
            # methods they're available through. Used downstream by PnC logic to decide
            # whether the EVCC has a valid contract certificate for any EMSP the SECC accepts.
            emsp_ext = _schema.decode('EMSPInfoExtension', ext_val)
            for ii, tup in enumerate(emsp_ext.get('emspIdentifiersTuplesList', []), start=1):
                ids = tup.get('emspIdentifiersList', [])
                methods = tup.get('authorizationMethodsList', [])
                logger.info(
                    'EMSPInfoExtension tuple %d: emsps=%s authMethods=%s',
                    ii, ids, methods,
                )

        elif ext_id == _UUID_AC_CHARGING_PARAMETERS:
            ac_params = _schema.decode('ACChargingParametersExtension', ext_val)
            logger.info(
                'ACChargingParametersExtension: nominalVoltages=%s gridFrequencies=%s numberOfPhases=%s',
                ac_params.get('nominalVoltageList'),
                ac_params.get('gridFrequencyList'),
                ac_params.get('numberOfPhases'),
            )

        elif ext_id == _UUID_EV_CHARACTERISTICS:
            ev_chars = _schema.decode('EVCharacteristicsExtension', ext_val)
            vehicle_indicator_section = ev_chars.get('vehicleIndicatorSection')
            vehicle_indicator_log = (
                f'communicated ({len(vehicle_indicator_section)} chars, redacted)'
                if vehicle_indicator_section else None
            )
            logger.info(
                'EVCharacteristics: WMI=%s VDS=%s VIS=%s sw=%s',
                ev_chars.get('worldManufacturerIdentifier'),
                ev_chars.get('vehicleDescriptorSection'),
                vehicle_indicator_log,
                ev_chars.get('evccSoftwareVersion'),
            )

        elif ext_id == _UUID_EVSE_CHARACTERISTICS:
            evse_chars = _schema.decode('EVSECharacteristicsExtension', ext_val)
            logger.info(
                'EVSECharacteristicsExtension: evseID=%s cpo=%s manufacturer=%s model=%s serial=%s firmware=%s',
                evse_chars.get('evseID'),
                evse_chars.get('chargePointOperator'),
                evse_chars.get('manufacturer'),
                evse_chars.get('model'),
                evse_chars.get('serialNumber'),
                evse_chars.get('firmwareVersion'),
            )

        elif ext_id == _UUID_CHARGING_SERVICE:
            # ChargingServiceExtension (was HighLevelCommunication) [V2G202-0084..0093].
            # Outer SEQUENCE wraps chargingServiceTuplesList; per-tuple field renames
            # cascade through securityProfileTupleList and (unused here) authorization /
            # energy-transfer lists. We only consult securityProfile here — pricingInformation
            # and controlMode information is decoded but not currently used by Josev.
            cs = _schema.decode('ChargingServiceExtension', ext_val)
            for cs_tuple in cs.get('chargingServiceTuplesList', []):
                for sp_tuple in cs_tuple.get('securityProfileTupleList', []):
                    offered_security_profiles.add(sp_tuple['securityProfile'])

    for preferred in preferred_security_profiles:
        if preferred in offered_security_profiles:
            sec = preferred
            break

    return [prt, ipv6addr, sec]

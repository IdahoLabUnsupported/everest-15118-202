// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
// Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
#include "esdp.hpp"
#include "log.hpp"
extern "C" {
    #include "all_asn1c_headers.h"
}

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG 1

#define SDP_VERSION         0x01
#define SDP_INVERSE_VERSION 0xfe
#define SDP_HEADER_LEN 8
#define ESDP_MIN_PAYLOAD_LEN 4
#define MAX_ESDP_RESPONSE_PAYLOAD_LEN 512

#define ESDP_SETUP_RESPONSE_TYPE 0x2022
#define ESDP_RESPONSE_TYPE       0x2024

// ESDPReq/Res: Extensions Offset field — bytes between end of this field and first extension [V2G202-0007]
// Set to 0x0000 for this edition of the standard (no additional parameters inserted)
#define ESDP_EXTENSIONS_OFFSET 0x0000

/* Extension UUIDs per Table 5 of ISO/PAS 15118-202:2025
   Extension UUIDs are still manual constants. The local ASN.1 file explicitly keeps
   extensionID as a raw OCTET STRING and omits the upstream extension object set, 
   so those UUID values are not present to extract from the current schema.*/
static const uint8_t EXT_UUID_CHARGING_INTERFACE[16]      = {0x3E,0xAE,0x3D,0xCB,0xE9,0x55,0x4A,0x1D,0x84,0xC6,0xB4,0xEE,0xF8,0x64,0x60,0xF3};
static const uint8_t EXT_UUID_ELECTRICAL_CHARGING_SYS[16] = {0x25,0x99,0x2A,0xFF,0x1A,0x58,0x45,0x5F,0xAF,0xFD,0xE5,0x8E,0xB6,0xF3,0x26,0x00};
static const uint8_t EXT_UUID_IPV6_SOCKET[16]             = {0xA2,0x39,0x8E,0x1B,0x3C,0x79,0x49,0x5D,0x9C,0xE1,0xBD,0x10,0x8D,0xEC,0x56,0x4E};
static const uint8_t EXT_UUID_TLS12_INFO[16]              = {0x7C,0x70,0x40,0x49,0xC4,0xDD,0x43,0x53,0x96,0x7E,0xDA,0xF2,0x1C,0x9D,0x45,0x3A};
static const uint8_t EXT_UUID_CHARGING_SERVICE[16]        = {0xFA,0xE8,0x27,0x04,0xEE,0xBA,0x48,0x92,0xAB,0xCC,0xFE,0x80,0x93,0xB8,0x63,0x12};
static const uint8_t EXT_UUID_EMSP_INFO[16]               = {0xAF,0xF5,0x7F,0x50,0x1E,0x6E,0x48,0x68,0x91,0x0C,0x4D,0x76,0xBF,0x35,0x29,0x6B};
static const uint8_t EXT_UUID_AC_CHARGING_PARAMETERS[16]  = {0xF7,0xF4,0x26,0x5C,0x38,0x44,0x44,0x7C,0x8D,0x7F,0xBB,0x38,0x57,0xA9,0xB6,0xAB};
static const uint8_t EXT_UUID_CONDUCTIVE_LIMITS[16]       = {0x27,0xD7,0x1E,0x41,0xEA,0x8C,0x4F,0xB2,0xBA,0x43,0x1E,0x1E,0x7E,0x60,0xE3,0x60};
static const uint8_t EXT_UUID_EV_CHARACTERISTICS[16]      = {0x5F,0xD6,0x33,0x44,0x58,0xDC,0x41,0x73,0xB9,0x26,0x08,0xF6,0x31,0x17,0xD4,0x11};
static const uint8_t EXT_UUID_EVSE_CHARACTERISTICS[16]    = {0xF0,0xE7,0x7C,0x3A,0xDC,0x41,0x47,0x73,0x98,0xC9,0xF1,0x77,0xF4,0x47,0x75,0xBB};

struct esdp_security_selection {
    bool tcp_only_supported;
    bool tls12_supported;
};

static bool esdp_supports_ac_charging(const struct v2g_context* ctx) {
    if (!ctx || ctx->is_dc_charger) {
        return false;
    }

    const auto& modes = ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode;
    for (uint16_t i = 0; i < modes.arrayLen; i++) {
        if (modes.array[i] == iso2_EnergyTransferModeType_AC_single_phase_core ||
            modes.array[i] == iso2_EnergyTransferModeType_AC_three_phase_core) {
            return true;
        }
    }

    return false;
}

static bool esdp_supports_dc_charging(const struct v2g_context* ctx) {
    if (!ctx) {
        return true;
    }

    const auto& modes = ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode;
    for (uint16_t i = 0; i < modes.arrayLen; i++) {
        switch (modes.array[i]) {
        case iso2_EnergyTransferModeType_DC_core:
        case iso2_EnergyTransferModeType_DC_extended:
        case iso2_EnergyTransferModeType_DC_combo_core:
        case iso2_EnergyTransferModeType_DC_unique:
            return true;
        default:
            break;
        }
    }

    return ctx->is_dc_charger;
}

static long esdp_ac_number_of_phases(const struct v2g_context* ctx) {
    long number_of_phases = 1;
    if (!ctx) {
        return number_of_phases;
    }

    const auto& modes = ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode;
    for (uint16_t i = 0; i < modes.arrayLen; i++) {
        if (modes.array[i] == iso2_EnergyTransferModeType_AC_three_phase_core) {
            number_of_phases = 3;
        } else if (modes.array[i] == iso2_EnergyTransferModeType_AC_single_phase_core && number_of_phases < 1) {
            number_of_phases = 1;
        }
    }

    return number_of_phases;
}

static long esdp_ac_nominal_voltage(const struct v2g_context* ctx) {
    if (!ctx || ctx->basic_config.evse_ac_nominal_voltage <= 0.0f) {
        return 230;
    }

    return static_cast<long>(ctx->basic_config.evse_ac_nominal_voltage + 0.5f);
}

static void esdp_add_energy_transfer_mode_tuple(SecurityProfileTuple_t* sp,
                                                EnergyTransferMode_t energy_transfer_mode) {
    EnergyTransferModeTuple_t *etm = (EnergyTransferModeTuple_t *)calloc(1, sizeof(EnergyTransferModeTuple_t));
    etm->energyTransferMode = energy_transfer_mode;
    etm->controlMode = ControlMode_ev_spontaneous;
    ASN_SEQUENCE_ADD(&sp->energyTransferModeTupleList.list, etm);
}

static ssize_t esdp_encode_extension_value(ESDPExtension_t* extension, const asn_TYPE_descriptor_t* type_descriptor,
                                           const void* value, size_t buffer_size, const char* extension_name) {
    if (!extension || !type_descriptor || !value || !extension_name) {
        dlog(DLOG_LEVEL_ERROR, "Invalid argument while encoding ESDP extension value");
        return -1;
    }

    uint8_t* buffer = (uint8_t*)calloc(buffer_size, sizeof(uint8_t));
    if (!buffer) {
        dlog(DLOG_LEVEL_ERROR, "Failed to allocate encode buffer for %s", extension_name);
        return -1;
    }

    asn_enc_rval_t enc_rval = oer_encode_to_buffer(type_descriptor, NULL, value, buffer, buffer_size);
    if (enc_rval.encoded <= 0) {
        dlog(DLOG_LEVEL_ERROR, "Failed to encode %s", extension_name);
        dlog(DLOG_LEVEL_ERROR, "OER encoding failed at type: %s",
             enc_rval.failed_type ? enc_rval.failed_type->name : "unknown");
        free(buffer);
        return -1;
    }
    if (enc_rval.encoded > INT_MAX) {
        dlog(DLOG_LEVEL_ERROR, "Encoded %s is too large to wrap in OCTET_STRING: %zd bytes",
             extension_name, enc_rval.encoded);
        free(buffer);
        return -1;
    }

    if (OCTET_STRING_fromBuf(&extension->extensionValue, (const char*)buffer, (int)enc_rval.encoded) != 0) {
        dlog(DLOG_LEVEL_ERROR, "Failed to wrap encoded %s in ESDPExtension extensionValue", extension_name);
        free(buffer);
        return -1;
    }

    free(buffer);
    return enc_rval.encoded;
}

static bool esdp_select_security(const struct v2g_context* ctx, const struct esdp_security_selection* selection,
                                 enum sdp_security* selected_security) {
    if (!selection || !selected_security) {
        return false;
    }

    if (selection->tls12_supported && (!ctx || ctx->local_tls_addr)) {
        *selected_security = SDP_SECURITY_TLS;
        return true;
    }

    if (selection->tcp_only_supported && (!ctx || ctx->local_tcp_addr)) {
        *selected_security = SDP_SECURITY_NONE;
        return true;
    }

    return false;
}

int esdp_validate_header(uint8_t* buffer, ssize_t recv_len, uint16_t expected_payload_type,
                                uint32_t max_esdp_payload_len, uint16_t expected_esdp_version,
                                uint32_t expected_payload_len) {
    /* Returns -1 for invalid V2GTP header, 1 for invalid ESDP Header (version, max payload size), and 0 otherwise*/

    uint16_t payload_type;
    uint32_t payload_len;
    uint16_t esdp_version;

    if (recv_len < SDP_HEADER_LEN) {
        dlog(DLOG_LEVEL_ERROR, "ESDP packet too short for V2GTP header: %zd bytes", recv_len);
        return -1;
    }

    if (buffer[0] != SDP_VERSION) {
        dlog(DLOG_LEVEL_ERROR, "Invalid SDP version in header of ESDP packet");
        return -1;
    }

    if (buffer[1] != SDP_INVERSE_VERSION) {
        dlog(DLOG_LEVEL_ERROR, "Invalid SDP inverse version in header of ESDP packet");
        return -1;
    }

    payload_type = (buffer[2] << 8) + buffer[3];
    if (payload_type != expected_payload_type) {
        dlog(DLOG_LEVEL_ERROR, "Invalid payload type: expected %" PRIu16 ", received %" PRIu16 " in header of ESDP packet",
             expected_payload_type, payload_type);
        return -1;
    }

    payload_len = (buffer[4] << 24) + (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
    if (payload_len > max_esdp_payload_len) {
        dlog(DLOG_LEVEL_ERROR, "Size of ESDPReq payload exceeds max limit. ESDPReq payload is %" PRIu32 " bytes while max limit is %" PRIu32 " bytes",
             payload_len, max_esdp_payload_len);
        return 1;
    }
    if (expected_payload_len > 0 && payload_len != expected_payload_len) {
        dlog(DLOG_LEVEL_ERROR,
             "Invalid ESDP payload length: expected %" PRIu32 ", received %" PRIu32,
             expected_payload_len, payload_len);
        return 1;
    }
    if (payload_len < ESDP_MIN_PAYLOAD_LEN) {
        dlog(DLOG_LEVEL_ERROR,
             "ESDP payload too short for version and next field: %" PRIu32 " bytes",
             payload_len);
        return 1;
    }
    if (recv_len != (ssize_t)(SDP_HEADER_LEN + payload_len)) {
        dlog(DLOG_LEVEL_ERROR,
             "ESDP datagram length mismatch: header reports %" PRIu32 " payload bytes, received %zd",
             payload_len, recv_len - SDP_HEADER_LEN);
        return 1;
    }
    
    /* Verify ESDP version per [V2G202-0002] in ISO/PAS 15118-202:2025. */
    esdp_version = (buffer[8] << 8) + buffer[9];    
    if (esdp_version != expected_esdp_version) {
    	dlog(DLOG_LEVEL_ERROR, "Unsupported ESDP Version: expected %" PRIu16 ", received %" PRIu16 " in ESDP Payload",
    	     expected_esdp_version, esdp_version);
     	dlog(DLOG_LEVEL_ERROR, "The last ESDP packet will be discarded since the ESDP version is unsupported");
     	return 1;
    } else {
        dlog(DLOG_LEVEL_INFO, "EVCC's reported ESDP Version: %" PRIu16, esdp_version);
    }
    
    return 0;
}

int encode_ESDPRes_Extensions(uint8_t* buffer_esdp, int offset, struct sockaddr_in6* addr, enum sdp_security security,
                              struct v2g_context* v2g_ctx) {
    bool supports_ac_charging = esdp_supports_ac_charging(v2g_ctx);
    bool supports_dc_charging = esdp_supports_dc_charging(v2g_ctx);
    if (!supports_ac_charging && !supports_dc_charging) {
        supports_dc_charging = true;
        dlog(DLOG_LEVEL_WARNING,
             "ESDP: no AC/DC energy-transfer mode configured; advertising DC as defensive fallback");
    }

    bool contract_payment_enabled = false;
    if (v2g_ctx) {
        for (const auto payment_option : v2g_ctx->evse_v2g_data.payment_option_list) {
            if (payment_option == iso2_paymentOptionType_Contract) {
                contract_payment_enabled = true;
                break;
            }
        }
    }
    const bool configured_emsp_identifiers =
        v2g_ctx && !v2g_ctx->supported_pnc_emsp_identifiers.empty();
    const bool advertise_pnc =
        security == SDP_SECURITY_TLS && contract_payment_enabled && configured_emsp_identifiers;
    bool advertise_eim = false;
    if (security == SDP_SECURITY_TLS && contract_payment_enabled && !configured_emsp_identifiers) {
        dlog(DLOG_LEVEL_WARNING,
             "ESDP: Contract/PnC is enabled but supported_pnc_emsp_identifiers is empty; "
             "not advertising pnc-2 or EMSPInfo");
    }
    if (configured_emsp_identifiers && security != SDP_SECURITY_TLS) {
        dlog(DLOG_LEVEL_WARNING,
             "ESDP: supported_pnc_emsp_identifiers configured but selected ESDP security is not TLS; "
             "not advertising pnc-2");
    }
    if (configured_emsp_identifiers && security == SDP_SECURITY_TLS && !contract_payment_enabled) {
        dlog(DLOG_LEVEL_WARNING,
             "ESDP: supported_pnc_emsp_identifiers configured but Contract payment is not enabled; "
             "not advertising pnc-2");
    }

    /* Create and populate ESDPExtensions */
    ESDPExtensions_t *extensions = (ESDPExtensions_t *)calloc(1, sizeof(ESDPExtensions_t));
    if (!extensions) {
        dlog(DLOG_LEVEL_ERROR, "Failed to allocate memory for extensions");
        return -1;
    }

    /* ChargingInterfaceExtension (UUID per Table 5 of ISO/PAS 15118-202:2025) [V2G202-0064] */
    /* Encodes SEQUENCE { chargingInterface, interfaceType } per §6.5.2 Table 6-8 */
    ESDPExtension_t *charging_interface_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
    if (!charging_interface_ext) {
        dlog(DLOG_LEVEL_ERROR, "Failed to allocate memory for Charging Interface Extension");
        return -1;
    }
    OCTET_STRING_fromBuf(&charging_interface_ext->extensionID, (const char *)EXT_UUID_CHARGING_INTERFACE, 16);
    ChargingInterfaceExtension_t ci_ext = {0};
    /* nullopt in basic_config means upper module never called handle_set_charging_parameters
     * with connector_type set; advertise CCS1/connector-plug as a defensive fallback and warn. */
    if (v2g_ctx && v2g_ctx->basic_config.charging_interface.has_value()) {
        ci_ext.chargingInterface = static_cast<ChargingInterface_t>(*v2g_ctx->basic_config.charging_interface);
        ci_ext.interfaceType     = static_cast<InterfaceType_t>(
            v2g_ctx->basic_config.interface_type.value_or(esdp::InterfaceType::ConnectorPlug));
    } else {
        ci_ext.chargingInterface = ChargingInterface_iec_62196_3_ee; /* CCS1 fallback */
        ci_ext.interfaceType     = InterfaceType_connector_plug;
        dlog(DLOG_LEVEL_WARNING,
             "ESDP: charging_interface not yet configured by upper module; "
             "advertising CCS1/connector-plug fallback. If this persists past the first "
             "SetupPhysicalValues call, the EVCC will see the wrong connector type.");
    }
    ssize_t ci_encoded = esdp_encode_extension_value(charging_interface_ext, &asn_DEF_ChargingInterfaceExtension,
                                                     &ci_ext, 128, "ChargingInterfaceExtension");
    if (ci_encoded <= 0) {
        return -1;
    }
    dlog(DLOG_LEVEL_INFO, "ESDP advertising ChargingInterface=%ld InterfaceType=%ld (%zd bytes)",
         ci_ext.chargingInterface, ci_ext.interfaceType, ci_encoded);
    ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, charging_interface_ext);

    /* ElectricalChargingSystemExtension (UUID per Table 5 of ISO/PAS 15118-202:2025) [V2G202-0054, 0067-0070] */
    /* Encodes SEQUENCE { electricalChargingSystemsList, controlPilotBCBToggleSupport OPTIONAL } per §6.5.3 Tables 9-11.
     * Advertised values come from the EvseV2G manifest config (mirrored into v2g_ctx at init), matching the
     * supported_DIN70121 / supported_ISO15118_2 capability-flag pattern. */
    ESDPExtension_t *ecs_wrapper_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
    OCTET_STRING_fromBuf(&ecs_wrapper_ext->extensionID, (const char *)EXT_UUID_ELECTRICAL_CHARGING_SYS, 16);
    ElectricalChargingSystemExtension_t *ecs_ext = (ElectricalChargingSystemExtension_t *)calloc(1, sizeof(ElectricalChargingSystemExtension_t));
    if (v2g_ctx && !v2g_ctx->supported_electrical_charging_systems.empty()) {
        for (esdp::ElectricalChargingSystem v : v2g_ctx->supported_electrical_charging_systems) {
            ElectricalChargingSystem_t *p = (ElectricalChargingSystem_t *)calloc(1, sizeof(ElectricalChargingSystem_t));
            *p = static_cast<ElectricalChargingSystem_t>(v);
            ASN_SEQUENCE_ADD(&ecs_ext->electricalChargingSystemsList.list, p);
        }
    } else {
        /* Defensive fallback when v2g_ctx is unavailable: advertise every value defined in Table 10. */
        static const ElectricalChargingSystem_t ecs_fallback[] = {
            ElectricalChargingSystem_iec61851_1_ed2,    ElectricalChargingSystem_iec61851_1_ed3,
            ElectricalChargingSystem_iec61851_1_ed4,    ElectricalChargingSystem_iec61851_23_ed1,
            ElectricalChargingSystem_iec61851_23_ed2,   ElectricalChargingSystem_iec61851_23_ed3,
            ElectricalChargingSystem_iec61851_23_3_ed1, ElectricalChargingSystem_sae_j1772_201602,
            ElectricalChargingSystem_sae_j1772_201710,  ElectricalChargingSystem_sae_j1772_202401,
            ElectricalChargingSystem_sae_j3068_202207,  ElectricalChargingSystem_sae_j3068_202409,
            ElectricalChargingSystem_sae_j3400_202409,
        };
        for (size_t i = 0; i < sizeof(ecs_fallback) / sizeof(ecs_fallback[0]); i++) {
            ElectricalChargingSystem_t *p = (ElectricalChargingSystem_t *)calloc(1, sizeof(ElectricalChargingSystem_t));
            *p = ecs_fallback[i];
            ASN_SEQUENCE_ADD(&ecs_ext->electricalChargingSystemsList.list, p);
        }
    }
    if (v2g_ctx && !v2g_ctx->supported_control_pilot_bcb_toggles.empty()) {
        ecs_ext->controlPilotBCBToggleSupport =
            (typeof(ecs_ext->controlPilotBCBToggleSupport))calloc(1, sizeof(*ecs_ext->controlPilotBCBToggleSupport));
        for (esdp::ControlPilotBcbToggleSupport v : v2g_ctx->supported_control_pilot_bcb_toggles) {
            ControlPilotBCBToggleSupport_t *p = (ControlPilotBCBToggleSupport_t *)calloc(1, sizeof(ControlPilotBCBToggleSupport_t));
            *p = static_cast<ControlPilotBCBToggleSupport_t>(v);
            ASN_SEQUENCE_ADD(&ecs_ext->controlPilotBCBToggleSupport->list, p);
        }
    }
    /* else: controlPilotBCBToggleSupport is OPTIONAL ([V2G202-0069/0070]); left absent. */
    ssize_t ecs_encoded = esdp_encode_extension_value(ecs_wrapper_ext, &asn_DEF_ElectricalChargingSystemExtension,
                                                      ecs_ext, 128, "ElectricalChargingSystemExtension");
    if (ecs_encoded <= 0) {
        return -1;
    }
    dlog(DLOG_LEVEL_INFO,
         "ESDP advertising ElectricalChargingSystemExtension electricalChargingSystems=%d controlPilotBCBToggleSupport=%d (%zd bytes)",
         ecs_ext->electricalChargingSystemsList.list.count,
         ecs_ext->controlPilotBCBToggleSupport ? ecs_ext->controlPilotBCBToggleSupport->list.count : 0,
         ecs_encoded);
    ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, ecs_wrapper_ext);

    /* IPv6SocketExtension (UUID per Table 5 of ISO/PAS 15118-202:2025) [V2G202-0071..0077]
     * Encodes SEQUENCE { ipv6SocketTuplesList } per §6.5.4 Table 12. Existing implementation
     * advertises a single tuple — the listening address/port — with a single SecurityProfile
     * in its securityProfileList, derived from the active security selection. The standard
     * permits multiple tuples (one per security profile) but the current EvseV2G impl listens
     * on a single port at a time, so a single tuple is correct.
     *
     * Port encoding: schema changed from OCTET STRING(SIZE(4)) to INTEGER(1..65535). asn1c
     * stores INTEGER as long; OER emits variable-length per X.696. addr->sin6_port is in
     * network byte order — convert to host order before assigning. */
    ESDPExtension_t *ipv6_socket_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
    OCTET_STRING_fromBuf(&ipv6_socket_ext->extensionID, (const char *)EXT_UUID_IPV6_SOCKET, 16);

    IPv6SocketExtension_t *ipv6_ext = (IPv6SocketExtension_t *)calloc(1, sizeof(IPv6SocketExtension_t));
    IPv6SocketTuple_t *ipv6_tuple = (IPv6SocketTuple_t *)calloc(1, sizeof(IPv6SocketTuple_t));
    OCTET_STRING_fromBuf(&ipv6_tuple->ipv6Address, (const char *)&addr->sin6_addr, sizeof(addr->sin6_addr));
    ipv6_tuple->tcpPort = (long)ntohs(addr->sin6_port);

    /* securityProfileList: one entry matching the current security selection. */
    SecurityProfile_t *sp = (SecurityProfile_t *)calloc(1, sizeof(SecurityProfile_t));
    switch (security) {
        case SDP_SECURITY_TLS:
            *sp = SecurityProfile_iso_15118_2_2014;  /* TLS 1.2 mapping per Table 17 */
            break;
        case SDP_SECURITY_NONE:
        default:
            *sp = SecurityProfile_tcpOnly;
            break;
    }
    ASN_SEQUENCE_ADD(&ipv6_tuple->securityProfileList.list, sp);
    ASN_SEQUENCE_ADD(&ipv6_ext->ipv6SocketTuplesList.list, ipv6_tuple);

    ssize_t ip_encoded = esdp_encode_extension_value(ipv6_socket_ext, &asn_DEF_IPv6SocketExtension,
                                                     ipv6_ext, 128, "IPv6SocketExtension");
    if (ip_encoded <= 0) {
        return -1;
    }
    dlog(DLOG_LEVEL_INFO,
         "ESDP advertising IPv6SocketExtension tuples=%d tcpPort=%ld securityProfile=%ld (%zd bytes)",
         ipv6_ext->ipv6SocketTuplesList.list.count, ipv6_tuple->tcpPort, *sp, ip_encoded);
    ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, ipv6_socket_ext);

    /* ChargingServiceExtension (UUID per Table 5 of ISO/PAS 15118-202:2025) [V2G202-0084..0093]
     * Encodes SEQUENCE { chargingServiceTuplesList, ... } per §6.5.6 Tables 14-20. The
     * previous HighLevelCommunication schema was renamed and significantly expanded:
     *   - top-level wrapper SEQUENCE instead of bare SEQUENCE OF
     *   - ChargingServiceTuple gets optional `pricingInformation`
     *   - SecurityProfileTuple's energy-transfer list now contains tuples that pair each
     *     EnergyTransferMode with a ControlMode (Table 20)
     *   - field renames: securityProfileTuple -> securityProfileTupleList,
     *                    authorizationMethod  -> authorizationMethodList,
     *                    energyTransferMode   -> energyTransferModeTupleList
     *   - enum integer values changed for HLCProtocol/AuthorizationMethod/EnergyTransferMode
     *     (wire-breaking — only meaningful when both ends use -202 schema)
     *
     * ControlMode choice: ev-spontaneous matches the existing pre-Item-6 semantics most
     * closely (SECC publishes limits, EV decides actual current/power within them — see
     * Table 20). evse-controlled or ev-planned belong to ISO 15118-20 service modes and
     * are not exercised by the DIN70121 / ISO 15118-2 tuples this implementation emits.
     *
     * pricingInformation: OPTIONAL ([V2G202-0086] — emit only if SECC can provide pricing).
     * The EvseV2G stack doesn't currently surface pricing capability, so the optional field
     * is omitted. A future change can add a manifest config knob to drive this. */
    ESDPExtension_t *hlc_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
    OCTET_STRING_fromBuf(&hlc_ext->extensionID, (const char *)EXT_UUID_CHARGING_SERVICE, 16);
    ChargingServiceExtension_t *cs_ext_payload =
        (ChargingServiceExtension_t *)calloc(1, sizeof(ChargingServiceExtension_t));

    /* First tuple: DIN SPEC 70121:2014 - TCP only, EIM, DC, ev-spontaneous.
     * DIN 70121 is DC-only, so do not advertise it for AC-only EVSE config. */
    if ((!v2g_ctx || (v2g_ctx->supported_protocols & (1 << V2G_PROTO_DIN70121))) && supports_dc_charging) {
        ChargingServiceTuple_t *t = (ChargingServiceTuple_t *)calloc(1, sizeof(ChargingServiceTuple_t));
        t->hlcProtocol = HLCProtocol_din_spec_70121_2014;

        SecurityProfileTuple_t *sp = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
        sp->securityProfile = SecurityProfile_tcpOnly;

        AuthorizationMethod_t *am = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
        *am = AuthorizationMethod_eim;
        ASN_SEQUENCE_ADD(&sp->authorizationMethodList.list, am);
        advertise_eim = true;

        esdp_add_energy_transfer_mode_tuple(sp, EnergyTransferMode_dc);

        ASN_SEQUENCE_ADD(&t->securityProfileTupleList.list, sp);
        ASN_SEQUENCE_ADD(&cs_ext_payload->chargingServiceTuplesList.list, t);
    }

    /* Second tuple: ISO 15118-2:2014 - TCP-only (EIM, configured DC/AC modes), plus
     * a second SecurityProfileTuple with iso-15118-2-2014. PnC-2 is advertised only
     * when TLS, Contract payment, and configured EMSP identifiers are all available. */
    if (!v2g_ctx || (v2g_ctx->supported_protocols & (1 << V2G_PROTO_ISO15118_2013))) {
        ChargingServiceTuple_t *t = (ChargingServiceTuple_t *)calloc(1, sizeof(ChargingServiceTuple_t));
        t->hlcProtocol = HLCProtocol_iso_15118_2_2014;

        /* SecurityProfileTuple 1: tcpOnly + EIM + configured energy-transfer modes */
        {
            SecurityProfileTuple_t *sp = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
            sp->securityProfile = SecurityProfile_tcpOnly;

            AuthorizationMethod_t *am = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
            *am = AuthorizationMethod_eim;
            ASN_SEQUENCE_ADD(&sp->authorizationMethodList.list, am);
            advertise_eim = true;

            if (supports_dc_charging) {
                esdp_add_energy_transfer_mode_tuple(sp, EnergyTransferMode_dc);
            }
            if (supports_ac_charging) {
                esdp_add_energy_transfer_mode_tuple(sp, EnergyTransferMode_ac);
            }

            ASN_SEQUENCE_ADD(&t->securityProfileTupleList.list, sp);
        }

        /* SecurityProfileTuple 2: iso-15118-2-2014 (TLS 1.2) + EIM and, when supported,
         * PnC-2 + configured modes. Only advertised if TLS is permitted by the SECC's
         * tls_security config. */
        if (security == SDP_SECURITY_TLS) {
            SecurityProfileTuple_t *sp = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
            sp->securityProfile = SecurityProfile_iso_15118_2_2014;

            AuthorizationMethod_t *am_eim = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
            *am_eim = AuthorizationMethod_eim;
            ASN_SEQUENCE_ADD(&sp->authorizationMethodList.list, am_eim);
            advertise_eim = true;
            if (advertise_pnc) {
                AuthorizationMethod_t *am_pnc = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
                *am_pnc = AuthorizationMethod_pnc_2;
                ASN_SEQUENCE_ADD(&sp->authorizationMethodList.list, am_pnc);
            }

            if (supports_dc_charging) {
                esdp_add_energy_transfer_mode_tuple(sp, EnergyTransferMode_dc);
            }
            if (supports_ac_charging) {
                esdp_add_energy_transfer_mode_tuple(sp, EnergyTransferMode_ac);
            }

            ASN_SEQUENCE_ADD(&t->securityProfileTupleList.list, sp);
        }

        ASN_SEQUENCE_ADD(&cs_ext_payload->chargingServiceTuplesList.list, t);
    }


    if (cs_ext_payload->chargingServiceTuplesList.list.count == 0) {
        dlog(DLOG_LEVEL_ERROR,
             "ESDP cannot encode ChargingServiceExtension with zero ChargingServiceTuple entries");
        return -1;
    }

    /* Encode and attach to extensions list. */
    ssize_t hlc_encoded = esdp_encode_extension_value(hlc_ext, &asn_DEF_ChargingServiceExtension,
                                                      cs_ext_payload, 256, "ChargingServiceExtension");
    if (hlc_encoded <= 0) {
        return -1;
    }
    dlog(DLOG_LEVEL_INFO,
         "ESDP advertising ChargingServiceExtension chargingServiceTuples=%d advertiseEIM=%s advertisePnC=%s (%zd bytes)",
         cs_ext_payload->chargingServiceTuplesList.list.count,
         advertise_eim ? "true" : "false",
         advertise_pnc ? "true" : "false",
         hlc_encoded);
    ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, hlc_ext);

    /* EMSPInfoExtension (UUID per Table 5 of ISO/PAS 15118-202:2025) [V2G202-0094..0097].
     * The tuple's authorizationMethodsList uses the generic AuthorizationMethod enum, so
     * EMSPInfo is not limited to PnC. Emit configured real EMSP IDs for every authorization
     * method this ESDPRes actually advertises. */
    if (configured_emsp_identifiers && (advertise_eim || advertise_pnc)) {
        ESDPExtension_t *emsp_ids_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
        OCTET_STRING_fromBuf(&emsp_ids_ext->extensionID, (const char *)EXT_UUID_EMSP_INFO, 16);

        EMSPInfoExtension_t *emsp_info = (EMSPInfoExtension_t *)calloc(1, sizeof(EMSPInfoExtension_t));
        EMSPIdentifiersTuple_t *emsp_tuple = (EMSPIdentifiersTuple_t *)calloc(1, sizeof(EMSPIdentifiersTuple_t));

        for (const auto& emsp_identifier : v2g_ctx->supported_pnc_emsp_identifiers) {
            UTF8String_t *emsp_id = (UTF8String_t *)calloc(1, sizeof(UTF8String_t));
            OCTET_STRING_fromBuf(emsp_id, emsp_identifier.c_str(), static_cast<int>(emsp_identifier.size()));
            ASN_SEQUENCE_ADD(&emsp_tuple->emspIdentifiersList.list, emsp_id);
        }

        if (advertise_eim) {
            AuthorizationMethod_t *auth_eim = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
            *auth_eim = AuthorizationMethod_eim;
            ASN_SEQUENCE_ADD(&emsp_tuple->authorizationMethodsList.list, auth_eim);
        }
        if (advertise_pnc) {
            AuthorizationMethod_t *auth_pnc = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
            *auth_pnc = AuthorizationMethod_pnc_2;
            ASN_SEQUENCE_ADD(&emsp_tuple->authorizationMethodsList.list, auth_pnc);
        }

        ASN_SEQUENCE_ADD(&emsp_info->emspIdentifiersTuplesList.list, emsp_tuple);

        ssize_t emsp_encoded = esdp_encode_extension_value(emsp_ids_ext, &asn_DEF_EMSPInfoExtension,
                                                           emsp_info, MAX_ESDP_RESPONSE_PAYLOAD_LEN,
                                                           "EMSPInfoExtension");
        if (emsp_encoded <= 0) {
            return -1;
        }
        dlog(DLOG_LEVEL_INFO,
             "ESDP advertising EMSPInfo for %zu EMSP identifier(s) advertiseEIM=%s advertisePnC=%s",
             v2g_ctx->supported_pnc_emsp_identifiers.size(),
             advertise_eim ? "true" : "false",
             advertise_pnc ? "true" : "false");
        ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, emsp_ids_ext);
    }

    /* ACChargingParametersExtension (UUID per Table 5 of ISO/PAS 15118-202:2025)
     * [V2G202-0098..0101]. Mandatory when AC charging is supported [V2G202-0060].
     * Field order follows Table 22: nominalVoltageList, gridFrequencyList, numberOfPhases. */
    if (supports_ac_charging) {
        ESDPExtension_t *ac_params_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
        OCTET_STRING_fromBuf(&ac_params_ext->extensionID, (const char *)EXT_UUID_AC_CHARGING_PARAMETERS, 16);

        ACChargingParametersExtension_t *ac_params =
            (ACChargingParametersExtension_t *)calloc(1, sizeof(ACChargingParametersExtension_t));

        long *nominal_voltage = (long *)calloc(1, sizeof(long));
        *nominal_voltage = esdp_ac_nominal_voltage(v2g_ctx);
        ASN_SEQUENCE_ADD(&ac_params->nominalVoltageList.list, nominal_voltage);

        if (v2g_ctx && !v2g_ctx->supported_ac_grid_frequencies.empty()) {
            for (long configured_frequency : v2g_ctx->supported_ac_grid_frequencies) {
                if (configured_frequency < 0 || configured_frequency > 255) {
                    dlog(DLOG_LEVEL_WARNING,
                         "ESDP: skipping invalid AC grid frequency %ld Hz; expected 0..255",
                         configured_frequency);
                    continue;
                }
                long *frequency = (long *)calloc(1, sizeof(long));
                *frequency = configured_frequency;
                ASN_SEQUENCE_ADD(&ac_params->gridFrequencyList.list, frequency);
            }
        }
        if (ac_params->gridFrequencyList.list.count == 0) {
            long *frequency = (long *)calloc(1, sizeof(long));
            *frequency = 50;
            ASN_SEQUENCE_ADD(&ac_params->gridFrequencyList.list, frequency);
            dlog(DLOG_LEVEL_WARNING, "ESDP: AC grid frequency list empty; advertising 50 Hz fallback");
        }

        ac_params->numberOfPhases = esdp_ac_number_of_phases(v2g_ctx);

        ssize_t ac_params_encoded = esdp_encode_extension_value(ac_params_ext, &asn_DEF_ACChargingParametersExtension,
                                                                ac_params, 128,
                                                                "ACChargingParametersExtension");
        if (ac_params_encoded <= 0) {
            return -1;
        }
        dlog(DLOG_LEVEL_INFO,
             "ESDP advertising ACChargingParameters nominalVoltage=%ld gridFrequencies=%d item(s) numberOfPhases=%ld",
             *nominal_voltage, ac_params->gridFrequencyList.list.count, ac_params->numberOfPhases);
        ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, ac_params_ext);
    }

    /* ConductiveChargingInterfaceLimitations extension (UUID per Table 5 of ISO/PAS 15118-202:2025) */
    /* Using placeholder values for Maximum contactor temperature */
    ESDPExtension_t *chrg_int_limits_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
    OCTET_STRING_fromBuf(&chrg_int_limits_ext->extensionID, (const char *)EXT_UUID_CONDUCTIVE_LIMITS, 16);
    ConductiveChargingInterfaceLimitationsExtension_t *chrg_int_limits =
        (ConductiveChargingInterfaceLimitationsExtension_t *)calloc(
            1, sizeof(ConductiveChargingInterfaceLimitationsExtension_t));
    chrg_int_limits -> maximumContactorCelsiusTemperature =
        v2g_ctx ? v2g_ctx->max_contactor_celsius_temperature : 80;
    ssize_t chrg_int_limits_encoded =
        esdp_encode_extension_value(chrg_int_limits_ext, &asn_DEF_ConductiveChargingInterfaceLimitationsExtension,
                                    chrg_int_limits, 128, "ConductiveChargingInterfaceLimitationsExtension");
    if (chrg_int_limits_encoded <= 0) {
        return -1;
    }
    dlog(DLOG_LEVEL_INFO,
         "ESDP advertising ConductiveChargingInterfaceLimitations maximumContactorCelsiusTemperature=%ld (%zd bytes)",
         chrg_int_limits->maximumContactorCelsiusTemperature,
         chrg_int_limits_encoded);
    ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, chrg_int_limits_ext);

    /* EVSECharacteristics extension (UUID per Table 5 of ISO/PAS 15118-202:2025). */
    ESDPExtension_t *evseChar_ext = (ESDPExtension_t *)calloc(1, sizeof(ESDPExtension_t));
    OCTET_STRING_fromBuf(&evseChar_ext->extensionID, (const char *)EXT_UUID_EVSE_CHARACTERISTICS, 16);
    EVSECharacteristicsExtension_t *evseChar =
        (EVSECharacteristicsExtension_t *)calloc(1, sizeof(EVSECharacteristicsExtension_t));
    evseChar->firmwareVersion = (UTF8String_t *)calloc(1, sizeof(UTF8String_t));
    const char evse_sw[] = "vXX.XX.XX";
    if (v2g_ctx && v2g_ctx->evse_v2g_data.evse_id.bytesLen > 0) {
        OCTET_STRING_fromBuf(&evseChar->evseID,
                             reinterpret_cast<const char*>(v2g_ctx->evse_v2g_data.evse_id.bytes),
                             v2g_ctx->evse_v2g_data.evse_id.bytesLen);
    } else {
        OCTET_STRING_fromBuf(&evseChar->evseID, "DE*CBY*ETE1*234", strlen("DE*CBY*ETE1*234"));
        dlog(DLOG_LEVEL_WARNING,
             "ESDP: EVSECharacteristics using fallback EVSEID because v2g_ctx->evse_v2g_data.evse_id is empty");
    }
    OCTET_STRING_fromBuf(evseChar->firmwareVersion, evse_sw, strlen(evse_sw));
    ssize_t evseChar_encoded = esdp_encode_extension_value(evseChar_ext, &asn_DEF_EVSECharacteristicsExtension,
                                                           evseChar, 128, "EVSECharacteristicsExtension");
    if (evseChar_encoded <= 0) {
        return -1;
    }
    dlog(DLOG_LEVEL_INFO,
         "ESDP advertising EVSECharacteristics evseIDLength=%zu firmwareVersionLength=%zu (%zd bytes)",
         evseChar->evseID.size,
         evseChar->firmwareVersion ? evseChar->firmwareVersion->size : 0,
         evseChar_encoded);
    ASN_SEQUENCE_ADD(&extensions->esdpExtensionsList, evseChar_ext);

    /* The following commented code block can be used for debugging asn1 encode output */
    //xer_fprint(stdout, &asn_DEF_ESDPExtensions, extensions);
    /* dlog(DLOG_LEVEL_INFO, "Number of ESDP extensions: %ld", extensions->esdpExtensionsList.list.count);
    for (int p = 0; p < extensions->esdpExtensionsList.list.count; p++) {
        ESDPExtension_t *temp = extensions->esdpExtensionsList.list.array[p];
        dlog(DLOG_LEVEL_INFO, "Extension UUID size: %ld, Value Size: %ld", temp->extensionID.size, temp->extensionValue.size);
    } */

    const size_t remaining_payload = MAX_ESDP_RESPONSE_PAYLOAD_LEN - (offset - SDP_HEADER_LEN);
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ESDPExtensions, NULL, extensions, buffer_esdp + offset, remaining_payload);
    if (ec.encoded <= 0) {
        dlog(DLOG_LEVEL_ERROR, "Failed to encode ESDP Extensions to ESDP buffer. encoded: %ld", ec.encoded);
        dlog(DLOG_LEVEL_ERROR, "OER encoding failed at type: %s",
             ec.failed_type ? ec.failed_type->name : "unknown");
        return -1;
    } else {
        dlog(DLOG_LEVEL_INFO, "ESDPRes extensions encoded: extensions=%d totalBytes=%zd",
             extensions->esdpExtensionsList.list.count, ec.encoded);
        offset += ec.encoded;
    }

    return offset;
}

/* Create ESDPSetupResponse packet (5-byte payload per Table 2 of ISO/PAS 15118-202:2025) */
int esdp_create_setup_response(uint8_t* buffer_esdp, uint16_t esdp_version) {
    int offset = SDP_HEADER_LEN;

    /* ESDP Version (2 bytes) */
    buffer_esdp[offset++] = (esdp_version >> 8) & 0xff;
    buffer_esdp[offset++] = esdp_version & 0xff;

    /* Maximum V2GTP Message Size (2 bytes) */
    buffer_esdp[offset++] = (ESDP_MAX_V2GTP_MESSAGE_SIZE >> 8) & 0xff;
    buffer_esdp[offset++] = ESDP_MAX_V2GTP_MESSAGE_SIZE & 0xff;

    /* Multiplexed ENP (1 byte): 0x00 = not supported */
    buffer_esdp[offset++] = 0x00;

    sdp_write_header(buffer_esdp, ESDP_SETUP_RESPONSE_TYPE, offset - SDP_HEADER_LEN);

    return offset;
}

/* Send ESDPSetupResponse in reply to an ESDPSetupRequest */
int esdp_send_setup_response(int esdp_socket, struct sdp_query* sdp_query, uint16_t esdp_version) {
    uint8_t buffer_esdp[SDP_HEADER_LEN + 5];
    int rv = 0;
    int response_size;

    response_size = esdp_create_setup_response(buffer_esdp, esdp_version);

    int return_status = sendto(esdp_socket, buffer_esdp, response_size, 0,
                               (struct sockaddr*)&sdp_query->remote_addr,
                               sizeof(struct sockaddr_in6));
    if (return_status != response_size) {
        rv = -1;
    }
    if (DEBUG) {
        char addrbuf[INET6_ADDRSTRLEN] = {0};
        const char* addr;
        int saved_errno = errno;

        addr = inet_ntop(AF_INET6, &sdp_query->remote_addr.sin6_addr, addrbuf, sizeof(addrbuf));
        if (rv == 0) {
            dlog(DLOG_LEVEL_INFO, "ESDPSetupResponse sent to [%s]:%" PRIu16, addr,
                 ntohs(sdp_query->remote_addr.sin6_port));
        } else {
            dlog(DLOG_LEVEL_ERROR, "Failed to send ESDPSetupResponse to [%s]:%" PRIu16 ": %s",
                 addr, ntohs(sdp_query->remote_addr.sin6_port), strerror(saved_errno));
        }
    }

    dlog(DLOG_LEVEL_INFO, "Size of ESDPSetupRes message sent: %d bytes", return_status);
    return rv;
}

/* Create response packet for ESDP */
int esdp_create_response(uint8_t* buffer_esdp, struct sockaddr_in6* addr, enum sdp_security security,
                         enum sdp_transport_protocol proto, struct v2g_context* v2g_ctx) {
    int offset = SDP_HEADER_LEN; // Header length is same for both SDP and ESDP
    int encode_return;

    // Write ESDP Version
    buffer_esdp[offset++] = (ESDP_VERSION >> 8) & 0xff;
    buffer_esdp[offset++] = ESDP_VERSION & 0xff;

    // Write ESDP Extensions Offset [V2G202-0007]: 0x0000 for this edition
    buffer_esdp[offset++] = (ESDP_EXTENSIONS_OFFSET >> 8) & 0xff;
    buffer_esdp[offset++] = ESDP_EXTENSIONS_OFFSET & 0xff;

    /* Now fill in the rest of the buffer with ESDP Extensions payload */
    encode_return = encode_ESDPRes_Extensions(buffer_esdp, offset, addr, security, v2g_ctx);
    if (encode_return <= 0) {
        dlog(DLOG_LEVEL_ERROR, "Failed to create ESDPRes: extension encoding failed");
        return -1;
    }
    offset = encode_return;

    /* now fill in the header with payload length */
    sdp_write_header(buffer_esdp, ESDP_RESPONSE_TYPE, offset - SDP_HEADER_LEN);

    return offset;
}

/*
 * Sends a response packet for ESDP
 */
int esdp_send_response(int esdp_socket, struct sdp_query* sdp_query) {
    uint8_t buffer_esdp[SDP_HEADER_LEN + MAX_ESDP_RESPONSE_PAYLOAD_LEN];
    int rv = 0;
    int esdp_response_size;

    /* at the moment we only understand TCP protocol */
    if (sdp_query->proto_requested != SDP_TRANSPORT_PROTOCOL_TCP) {
        dlog(DLOG_LEVEL_ERROR, "ESDP requested unsupported protocol 0x%02x, announcing nothing",
             sdp_query->proto_requested);
        return 1;
    }

    switch (sdp_query->security_requested) {
    case SDP_SECURITY_TLS:
        if (sdp_query->v2g_ctx->local_tls_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested TLS, announcing TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tls_addr, SDP_SECURITY_TLS,
                                SDP_TRANSPORT_PROTOCOL_TCP, sdp_query->v2g_ctx);
            break;
        }
        if (sdp_query->v2g_ctx->local_tcp_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested TLS, announcing NO-TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tcp_addr, SDP_SECURITY_NONE,
                                SDP_TRANSPORT_PROTOCOL_TCP, sdp_query->v2g_ctx);
            break;
        }
        dlog(DLOG_LEVEL_ERROR, "ESDP requested TLS, announcing nothing");
        return 1;

    case SDP_SECURITY_NONE:
        if (sdp_query->v2g_ctx->local_tcp_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested NO-TLS, announcing NO-TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tcp_addr, SDP_SECURITY_NONE,
                                SDP_TRANSPORT_PROTOCOL_TCP, sdp_query->v2g_ctx);
            break;
        }
        if (sdp_query->v2g_ctx->local_tls_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested NO-TLS, announcing TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tls_addr, SDP_SECURITY_TLS,
                                SDP_TRANSPORT_PROTOCOL_TCP, sdp_query->v2g_ctx);
            break;
        }
        dlog(DLOG_LEVEL_ERROR, "ESDP requested NO-TLS, announcing nothing");
        return 1;

    default:
        dlog(DLOG_LEVEL_ERROR, "ESDP requested unsupported security 0x%02x, announcing nothing",
             sdp_query->security_requested);
        return 1;
    }

    if (esdp_response_size <= 0) {
        dlog(DLOG_LEVEL_ERROR, "ESDP response creation failed, announcing nothing");
        return 1;
    }

    int return_status = sendto(esdp_socket, buffer_esdp, esdp_response_size, 0, (struct sockaddr*)&sdp_query->remote_addr,
        sizeof(struct sockaddr_in6));

    if (return_status != esdp_response_size) {
        rv = -1;
    }
    if (DEBUG) {
        char addrbuf[INET6_ADDRSTRLEN] = {0};
        const char* addr;
        int saved_errno = errno;

        addr = inet_ntop(AF_INET6, &sdp_query->remote_addr.sin6_addr, addrbuf, sizeof(addrbuf));
        if (rv == 0) {
            dlog(DLOG_LEVEL_INFO, "sendto([%s]:%" PRIu16 ") succeeded for ESDP", addr, ntohs(sdp_query->remote_addr.sin6_port));
        } else {
            dlog(DLOG_LEVEL_ERROR, "sendto([%s]:%" PRIu16 ") failed: %s for ESDP", addr, ntohs(sdp_query->remote_addr.sin6_port),
                 strerror(saved_errno));
        }
    }
    
    dlog(DLOG_LEVEL_INFO, "Size of ESDPRes message sent: %zu bytes", return_status);

    return rv;
}

// Function to decode ESDP extensions
int decode_esdp_extensions(const ESDPExtensions_t *extensions, struct sdp_query* sdp_query) {
    /* Returns 1 if unable to decode ESDP extensions and 0 otherwise */
    /* Requested Security and Transport must be updated in the "sdp_query" struct with the values decoded in ChargingService extension.
        Currently these are hardcoded to No-TLS and TCP respectively in "sdp_listen" under esdp */
    if (!extensions) {
        dlog(DLOG_LEVEL_ERROR, "No ESDP extensions to decode");
        return 1;
    }
    if (!sdp_query) {
        dlog(DLOG_LEVEL_ERROR, "No SDP query context available for ESDP extension decode");
        return 1;
    }
    struct esdp_security_selection security_selection = {
        .tcp_only_supported = false,
        .tls12_supported = false,
    };

    for (int i = 0; i < extensions->esdpExtensionsList.list.count; i++) {
        ESDPExtension_t *ext = extensions->esdpExtensionsList.list.array[i];
        if (ext) {
            uint8_t *extensionVal_buf = ext -> extensionValue.buf;
            ssize_t extensionVal_size = ext -> extensionValue.size;

            if (memcmp(ext->extensionID.buf, EXT_UUID_CHARGING_INTERFACE, 16) == 0) {
                /* ChargingInterfaceExtension [V2G202-0064] */
                {
                    ChargingInterfaceExtension_t *ci_ext = NULL;
                    asn_dec_rval_t rval_chrg_int = oer_decode(NULL, &asn_DEF_ChargingInterfaceExtension,
                        (void **)&ci_ext, extensionVal_buf, extensionVal_size);

                    if (rval_chrg_int.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded ChargingInterfaceExtension");
                        const char *iface_type_str = (ci_ext->interfaceType == InterfaceType_socket_inlet)
                            ? "socket_inlet" : "connector_plug";
                        switch(ci_ext->chargingInterface) {
                            case ChargingInterface_iec_62196_2_type_1:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-2 Type 1 (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_2_type_2:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-2 Type 2 (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_2_type_4:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-2 Type 4 (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_aa:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 AA / CHAdeMO (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_bb:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 BB / GB/T 20234.3 (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_ee:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 EE / CCS1/Combo1 (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_ff:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 FF / CCS2/Combo2 (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_gg:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 GG / ChaoJi (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_jj:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 JJ / Ultra ChaoJi (%s)", iface_type_str);
                                break;
                            case ChargingInterface_iec_62196_3_hh:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: IEC 62196-3 HH / MCS (%s)", iface_type_str);
                                break;
                            case ChargingInterface_sae_j3400:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: SAE J3400 / NACS (%s)", iface_type_str);
                                break;
                            default:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: unknown (%ld) (%s)",
                                    ci_ext->chargingInterface, iface_type_str);
                                break;
                        }
                        /* basic_config.charging_interface is std::nullopt until the upper module has
                         * called handle_set_charging_parameters with connector_type set; skip mismatch
                         * detection in that case (a complementary warning is logged at encode time). */
                        if (sdp_query->v2g_ctx &&
                            sdp_query->v2g_ctx->basic_config.charging_interface.has_value() &&
                            ci_ext->chargingInterface !=
                                static_cast<ChargingInterface_t>(*sdp_query->v2g_ctx->basic_config.charging_interface)) {
                            dlog(DLOG_LEVEL_WARNING,
                                 "Connector type mismatch, adapter likely being used: EV advertised ChargingInterface=%ld, "
                                 "EVSE configured ChargingInterface=%ld",
                                 ci_ext->chargingInterface,
                                 static_cast<long>(*sdp_query->v2g_ctx->basic_config.charging_interface));
                        }
                        ASN_STRUCT_FREE(asn_DEF_ChargingInterfaceExtension, ci_ext);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode ChargingInterfaceExtension");
                    }
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_ELECTRICAL_CHARGING_SYS, 16) == 0) {
                /* ElectricalChargingSystemExtension [V2G202-0067..0070] per §6.5.3 Tables 9-11 */
                ElectricalChargingSystemExtension_t *ev_ecs = NULL;
                asn_dec_rval_t rval_ecs = oer_decode(NULL, &asn_DEF_ElectricalChargingSystemExtension, (void **)&ev_ecs,
                                extensionVal_buf, extensionVal_size);

                if (rval_ecs.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded ElectricalChargingSystemExtension");
                    for (int k = 0; k < ev_ecs->electricalChargingSystemsList.list.count; k++) {
                        switch(*ev_ecs->electricalChargingSystemsList.list.array[k]) {
                            case ElectricalChargingSystem_iec61851_1_ed2:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-1 Ed-2", k+1); break;
                            case ElectricalChargingSystem_iec61851_1_ed3:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-1 Ed-3", k+1); break;
                            case ElectricalChargingSystem_iec61851_1_ed4:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-1 Ed-4", k+1); break;
                            case ElectricalChargingSystem_iec61851_23_ed1:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-23 Ed-1", k+1); break;
                            case ElectricalChargingSystem_iec61851_23_ed2:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-23 Ed-2", k+1); break;
                            case ElectricalChargingSystem_iec61851_23_ed3:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-23 Ed-3", k+1); break;
                            case ElectricalChargingSystem_iec61851_23_3_ed1:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: IEC 61851-23-3 Ed-1", k+1); break;
                            case ElectricalChargingSystem_sae_j1772_201602:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: SAE J1772_201602", k+1); break;
                            case ElectricalChargingSystem_sae_j1772_201710:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: SAE J1772_201710", k+1); break;
                            case ElectricalChargingSystem_sae_j1772_202401:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: SAE J1772_202401", k+1); break;
                            case ElectricalChargingSystem_sae_j3068_202207:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: SAE J3068_202207", k+1); break;
                            case ElectricalChargingSystem_sae_j3068_202409:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: SAE J3068_202409", k+1); break;
                            case ElectricalChargingSystem_sae_j3400_202409:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: SAE J3400_202409", k+1); break;
                            default:
                                dlog(DLOG_LEVEL_INFO, "     ElectricalChargingSystem[%d]: unknown (%ld)", k+1,
                                     (long)*ev_ecs->electricalChargingSystemsList.list.array[k]); break;
                        }
                    }
                    if (ev_ecs->controlPilotBCBToggleSupport) {
                        for (int k = 0; k < ev_ecs->controlPilotBCBToggleSupport->list.count; k++) {
                            switch(*ev_ecs->controlPilotBCBToggleSupport->list.array[k]) {
                                case ControlPilotBCBToggleSupport_slacValidation:
                                    dlog(DLOG_LEVEL_INFO, "     ControlPilotBCBToggleSupport[%d]: slacValidation", k+1); break;
                                case ControlPilotBCBToggleSupport_wakeup:
                                    dlog(DLOG_LEVEL_INFO, "     ControlPilotBCBToggleSupport[%d]: wakeup", k+1); break;
                                default:
                                    dlog(DLOG_LEVEL_INFO, "     ControlPilotBCBToggleSupport[%d]: unknown (%ld)", k+1,
                                         (long)*ev_ecs->controlPilotBCBToggleSupport->list.array[k]); break;
                            }
                        }
                    }
                    ASN_STRUCT_FREE(asn_DEF_ElectricalChargingSystemExtension, ev_ecs);
                } else {
                    dlog(DLOG_LEVEL_ERROR, "Failed to decode ElectricalChargingSystemExtension");
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_IPV6_SOCKET, 16) == 0) {
                /* IPv6SocketExtension belongs in ESDPRes only.
                 * Per [V2G202-0072], the EVCC shall not include it in ESDPReq. */
                dlog(DLOG_LEVEL_WARNING,
                     "ESDPReq payload includes IPv6 Socket extension, violating [V2G202-0072]; ignoring");
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_TLS12_INFO, 16) == 0) {
                /* TLS12InfoExtension [V2G202-0078..0083] per §6.5.5 Table 13.
                 * The EVCC sends RFC 6066 cert_sha1_hash values for V2G root certificates
                 * it can use to validate the SECC's TLS 1.2 server certificate. This first
                 * pass decodes and logs the identifiers; actual multi-chain SECC certificate
                 * selection would require additional runtime certificate-store plumbing. */
                TLS12InfoExtension_t *tls12_info = NULL;
                asn_dec_rval_t rval_tls12 = oer_decode(NULL, &asn_DEF_TLS12InfoExtension, (void **)&tls12_info,
                    extensionVal_buf, extensionVal_size);

                if (rval_tls12.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded TLS12Info extension (%d root key identifier(s))",
                         tls12_info->caRootKeyIdentifiersList.list.count);
                    for (int ii = 0; ii < tls12_info->caRootKeyIdentifiersList.list.count; ii++) {
                        OCTET_STRING_t *key_id = tls12_info->caRootKeyIdentifiersList.list.array[ii];
                        if (!key_id || key_id->size != 20) {
                            dlog(DLOG_LEVEL_WARNING,
                                 "     TLS12Info CA root key identifier[%d] has invalid size %ld, expected 20",
                                 ii + 1, (long)(key_id ? key_id->size : 0));
                            continue;
                        }

                        char key_id_hex[41] = {0};
                        for (int jj = 0; jj < 20; jj++) {
                            snprintf(&key_id_hex[jj * 2], sizeof(key_id_hex) - (jj * 2),
                                     "%02X", key_id->buf[jj]);
                        }
                        dlog(DLOG_LEVEL_INFO, "     TLS12Info CA root key identifier[%d]: %s", ii + 1, key_id_hex);
                    }
                    ASN_STRUCT_FREE(asn_DEF_TLS12InfoExtension, tls12_info);
                } else {
                    dlog(DLOG_LEVEL_ERROR, "Failed to decode TLS12Info extension");
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_CHARGING_SERVICE, 16) == 0) {
                /* ChargingServiceExtension (was HighLevelCommunication) [V2G202-0084..0093]
                 * Field renames since pre-202:
                 *   ev_hlc->list                          -> cs_ext->chargingServiceTuplesList.list
                 *   tuple->securityProfileTuple           -> tuple->securityProfileTupleList
                 *   sp_tuple->authorizationMethod         -> sp_tuple->authorizationMethodList
                 *   sp_tuple->energyTransferMode          -> sp_tuple->energyTransferModeTupleList
                 *     (now SEQUENCE OF EnergyTransferModeTuple { energyTransferMode, controlMode }) */
                ChargingServiceExtension_t *ev_cs = NULL;
                asn_dec_rval_t rval_hlc = oer_decode(NULL, &asn_DEF_ChargingServiceExtension, (void **)&ev_cs,
                    extensionVal_buf, extensionVal_size);

                if (rval_hlc.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded ChargingService extension");
                    for (int ii = 0; ii < ev_cs->chargingServiceTuplesList.list.count; ii++) {
                        ChargingServiceTuple_t *tuple = ev_cs->chargingServiceTuplesList.list.array[ii];
                        switch (tuple->hlcProtocol) {
                            case HLCProtocol_din_spec_70121_2014:
                            case HLCProtocol_din_ts_70121_2024:
                            case HLCProtocol_iso_15118_2_2014:
                            case HLCProtocol_iso_15118_2_2026:
                            case HLCProtocol_iso_15118_20_2022:
                            case HLCProtocol_iso_15118_20_2022_amd1:
                            case HLCProtocol_sae_j2847_2_202309:
                                break;
                            default:
                                dlog(DLOG_LEVEL_ERROR, "    Unknown HLC Protocol (%ld)", tuple->hlcProtocol);
                                break;
                        }
                        if (tuple->pricingInformation) {
                            /* OPTIONAL per [V2G202-0086]; recognise + log but pricing handling
                             * isn't wired into the EvseV2G stack. Just count entries. */
                            dlog(DLOG_LEVEL_INFO, "    PricingInformation: %d pricing type(s) advertised",
                                 tuple->pricingInformation->pricingTypesList.list.count);
                        }
	                        for (int jj = 0; jj < tuple->securityProfileTupleList.list.count; jj++) {
	                            SecurityProfileTuple_t *sp_tuple = tuple->securityProfileTupleList.list.array[jj];
	                            switch(sp_tuple->securityProfile) {
	                                case SecurityProfile_tcpOnly:
	                                    security_selection.tcp_only_supported = true;
	                                    break;
	                                case SecurityProfile_iso_15118_2_2014:
	                                    security_selection.tls12_supported = true;
	                                    break;
	                                case SecurityProfile_iso_15118_2_2026:
	                                    /* ISO 15118-2 2nd edition (TLS 1.3 with stricter requirements).
	                                     * Recognised but no runtime support yet — needs Item 6 follow-on
	                                     * (TLS 1.3 handshake configuration + cert/key handling updates). */
	                                    dlog(DLOG_LEVEL_INFO, "    Security Profile iso-15118-2-2026 advertised (no runtime support yet)");
	                                    break;
	                                case SecurityProfile_iso_15118_20_2022:
	                                    /* ISO 15118-20 (TLS 1.3 mutual). Same status as 2026 above. */
	                                    dlog(DLOG_LEVEL_INFO, "    Security Profile iso-15118-20-2022 advertised (no runtime support yet)");
	                                    break;
	                                default:
	                                    dlog(DLOG_LEVEL_ERROR, "    Unknown Security Profile (%ld)", sp_tuple->securityProfile);
	                                    break;
	                            }
                            for (int kk = 0; kk < sp_tuple->authorizationMethodList.list.count; kk++) {
                                AuthorizationMethod_t *auth_method = sp_tuple->authorizationMethodList.list.array[kk];
                                switch(*auth_method) {
                                    case AuthorizationMethod_eim:
                                    case AuthorizationMethod_pnc_2:
                                    case AuthorizationMethod_pnc_20:
                                        break;
                                    default:
                                        dlog(DLOG_LEVEL_ERROR, "    Unknown Authorization Method (%ld)", *auth_method);
                                        break;
                                }
                            }
                            /* Each entry is now EnergyTransferModeTuple { energyTransferMode, controlMode }. */
                            for (int kk = 0; kk < sp_tuple->energyTransferModeTupleList.list.count; kk++) {
                                EnergyTransferModeTuple_t *etm = sp_tuple->energyTransferModeTupleList.list.array[kk];
                                switch(etm->energyTransferMode) {
                                    case EnergyTransferMode_dc:
                                    case EnergyTransferMode_dc_bpt:
                                    case EnergyTransferMode_ac:
                                    case EnergyTransferMode_ac_bpt:
                                        break;
                                    default:
                                        dlog(DLOG_LEVEL_ERROR, "    Unknown Energy Transfer Mode (%ld)", etm->energyTransferMode);
                                        break;
                                }
                                switch(etm->controlMode) {
                                    case ControlMode_ev_planned:
                                    case ControlMode_ev_spontaneous:
                                    case ControlMode_evse_controlled:
                                        break;
                                    default:
                                        dlog(DLOG_LEVEL_ERROR, "    Unknown Control Mode (%ld)", etm->controlMode);
                                        break;
                                }
                            }
                        }
                    }
	                    ASN_STRUCT_FREE(asn_DEF_ChargingServiceExtension, ev_cs);
	                } else {
	                    dlog(DLOG_LEVEL_ERROR, "Failed to decode ChargingService extension");
	                    return 1;
	                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_EMSP_INFO, 16) == 0) {
                /* EMSPInfoExtension [V2G202-0094..0097] per §6.5.7 Table 21.
                 * Decode and log the EMSP identifiers with their advertised authorization
                 * methods. Downstream authorization selection could consult this list for
                 * EIM, PnC, or future authorization methods. */
                EMSPInfoExtension_t *ev_emsp = NULL;
                asn_dec_rval_t rval_emsp = oer_decode(NULL, &asn_DEF_EMSPInfoExtension, (void **)&ev_emsp,
                    extensionVal_buf, extensionVal_size);

                if (rval_emsp.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded EMSPInfo extension (%d tuple(s))",
                         ev_emsp->emspIdentifiersTuplesList.list.count);
                    for (int ii = 0; ii < ev_emsp->emspIdentifiersTuplesList.list.count; ii++) {
                        EMSPIdentifiersTuple_t *tuple = ev_emsp->emspIdentifiersTuplesList.list.array[ii];
                        for (int jj = 0; jj < tuple->emspIdentifiersList.list.count; jj++) {
                            UTF8String_t *id = tuple->emspIdentifiersList.list.array[jj];
                            dlog(DLOG_LEVEL_INFO, "     EMSP[%d.%d]: %.*s", ii+1, jj+1,
                                 (int)id->size, (const char *)id->buf);
                        }
                        for (int jj = 0; jj < tuple->authorizationMethodsList.list.count; jj++) {
                            AuthorizationMethod_t *am = tuple->authorizationMethodsList.list.array[jj];
                            const char *name = (*am == AuthorizationMethod_eim) ? "eim"
                                             : (*am == AuthorizationMethod_pnc_2) ? "pnc-2"
                                             : (*am == AuthorizationMethod_pnc_20) ? "pnc-20" : "unknown";
                            dlog(DLOG_LEVEL_INFO, "     EMSP[%d] AuthMethod[%d]: %s", ii+1, jj+1, name);
                        }
                    }
                    ASN_STRUCT_FREE(asn_DEF_EMSPInfoExtension, ev_emsp);
                } else {
                    dlog(DLOG_LEVEL_ERROR, "Failed to decode EMSPInfo extension");
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_AC_CHARGING_PARAMETERS, 16) == 0) {
                /* ACChargingParametersExtension [V2G202-0098..0101] per §6.5.8 Table 22. */
                ACChargingParametersExtension_t *ac_params = NULL;
                asn_dec_rval_t rval_ac_params = oer_decode(NULL, &asn_DEF_ACChargingParametersExtension,
                    (void **)&ac_params, extensionVal_buf, extensionVal_size);

                if (rval_ac_params.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded ACChargingParameters extension");
                    for (int ii = 0; ii < ac_params->nominalVoltageList.list.count; ii++) {
                        dlog(DLOG_LEVEL_INFO, "     AC nominalVoltage[%d]: %ld V",
                             ii + 1, *ac_params->nominalVoltageList.list.array[ii]);
                    }
                    for (int ii = 0; ii < ac_params->gridFrequencyList.list.count; ii++) {
                        dlog(DLOG_LEVEL_INFO, "     AC gridFrequency[%d]: %ld Hz",
                             ii + 1, *ac_params->gridFrequencyList.list.array[ii]);
                    }
                    dlog(DLOG_LEVEL_INFO, "     AC numberOfPhases: %ld", ac_params->numberOfPhases);
                    ASN_STRUCT_FREE(asn_DEF_ACChargingParametersExtension, ac_params);
                } else {
                    dlog(DLOG_LEVEL_ERROR, "Failed to decode ACChargingParameters extension");
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_CONDUCTIVE_LIMITS, 16) == 0) {
                /* ConductiveChargingInterfaceLimitations extension */
                ConductiveChargingInterfaceLimitationsExtension_t *ev_interface_limits = NULL;
                asn_dec_rval_t rval_int_limits = oer_decode(NULL, &asn_DEF_ConductiveChargingInterfaceLimitationsExtension,
                                (void **)&ev_interface_limits, extensionVal_buf, extensionVal_size);

                if (rval_int_limits.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded Conductive Charging Interface Limitations extension");
                    dlog(DLOG_LEVEL_INFO, "     Maximum Contactor Temp: %ld [C]\n", ev_interface_limits->maximumContactorCelsiusTemperature);
                    ASN_STRUCT_FREE(asn_DEF_ConductiveChargingInterfaceLimitationsExtension, ev_interface_limits);
                } else {
                    dlog(DLOG_LEVEL_ERROR, "Failed to decode Conductive Charging Interface Limitations extension");
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_EV_CHARACTERISTICS, 16) == 0) {
                /* EVCharacteristics extension */
                EVCharacteristicsExtension_t *evChar = NULL;
                asn_dec_rval_t rval_evChar = oer_decode(NULL, &asn_DEF_EVCharacteristicsExtension, (void **)&evChar,
                                extensionVal_buf, extensionVal_size);

                if (rval_evChar.code == RC_OK) {
                    dlog(DLOG_LEVEL_INFO, "Successfully decoded EV Characteristics extension");
                    if (evChar->worldManufacturerIdentifier.size > 0) {
                        dlog(DLOG_LEVEL_INFO, "     WMI: %.*s",
                             (int)evChar->worldManufacturerIdentifier.size,
                             evChar->worldManufacturerIdentifier.buf);
                    } else {
                        dlog(DLOG_LEVEL_WARNING, "World Manufacturer Identifier was NOT communicated");
                    }
                    if (evChar->vehicleDescriptorSection && evChar->vehicleDescriptorSection->size > 0) {
                        dlog(DLOG_LEVEL_INFO, "     VDS: %.*s",
                             (int)evChar->vehicleDescriptorSection->size,
                             evChar->vehicleDescriptorSection->buf);
                    } else {
                        dlog(DLOG_LEVEL_INFO, "     VDS: not communicated");
                    }
                    if (evChar->vehicleIndicatorSection && evChar->vehicleIndicatorSection->size > 0) {
                        dlog(DLOG_LEVEL_INFO, "     VIS: communicated (%zu bytes, redacted)",
                             evChar->vehicleIndicatorSection->size);
                    } else {
                        dlog(DLOG_LEVEL_INFO, "     VIS: not communicated");
                    }
                    if (evChar->evccSoftwareVersion && evChar->evccSoftwareVersion->size > 0) {
                        dlog(DLOG_LEVEL_INFO, "     EVCC Software Version: %.*s\n",
                            (int)evChar->evccSoftwareVersion->size, evChar->evccSoftwareVersion->buf);
                    } else {
                        dlog(DLOG_LEVEL_WARNING, "EVCC Software version was NOT communicated");
                    }
                    ASN_STRUCT_FREE(asn_DEF_EVCharacteristicsExtension, evChar);
                } else {
                    dlog(DLOG_LEVEL_ERROR, "Failed to decode EV Characteristics extension");
                }
            } else if (memcmp(ext->extensionID.buf, EXT_UUID_EVSE_CHARACTERISTICS, 16) == 0) {
                /* EVSECharacteristics extension (ChargingStationCharacteristics) */
                dlog(DLOG_LEVEL_WARNING, "ESDPReq payload includes EVSECharacteristics extension");
            } else {
                /* Unknown UUID, silently ignored per [V2G202-0047] */
                dlog(DLOG_LEVEL_WARNING, "Unknown extension UUID, ignoring per [V2G202-0047]");
            }
        }
    }

    if (!esdp_select_security(sdp_query->v2g_ctx, &security_selection, &sdp_query->security_requested)) {
        dlog(DLOG_LEVEL_WARNING,
             "ESDPReq did not advertise a mutually supported security profile; ignoring request");
        return 1;
    }

    /* Since Transport protocol is not included in HLC Extension under ESDP Standardized extensions,
        this is currently being hardcoded*/
    sdp_query->proto_requested = SDP_TRANSPORT_PROTOCOL_TCP;

    return 0;
}

// Function to decode ESDP extensions in V2GTP payload in ESDPReq message
int decode_esdp_payload(uint8_t* buffer, struct sdp_query* sdp_query, ssize_t recv_len) {
    /* Returns 1 if unable to decode esdp extensions and 0 otherwise*/

    int dec_std_ext_return;
    if (recv_len < SDP_HEADER_LEN + 4) {
        dlog(DLOG_LEVEL_WARNING,
             "ESDPReq too short to contain version and extensions offset: %zd bytes",
             recv_len);
        return 1;
    }

    uint32_t payload_len = (buffer[4] << 24) + (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
    if (payload_len != (uint32_t)(recv_len - SDP_HEADER_LEN)) {
        dlog(DLOG_LEVEL_WARNING,
             "ESDP payload length mismatch: reported %" PRIu32 " bytes, received %zd bytes",
             payload_len, recv_len - SDP_HEADER_LEN);
        return 1;
    }

    uint16_t extensions_offset = (buffer[SDP_HEADER_LEN + 2] << 8) + buffer[SDP_HEADER_LEN + 3];
    size_t payload_end = SDP_HEADER_LEN + payload_len;
    size_t extensions_start = SDP_HEADER_LEN + 4 + extensions_offset;
    if (extensions_start > payload_end) {
        dlog(DLOG_LEVEL_WARNING, "ESDP extensions offset %" PRIu16 " points beyond payload", extensions_offset);
        return 1;
    }

    size_t asn1_payload_size = payload_end - extensions_start;
    if (asn1_payload_size == 0) {
        dlog(DLOG_LEVEL_WARNING, "ESDP extensions payload is empty");
        return 1;
    }

    /* Decode the buffer into "extensions" object*/
    ESDPExtensions_t *extensions = NULL;

    asn_dec_rval_t rval = asn_decode(NULL, ATS_CANONICAL_OER, &asn_DEF_ESDPExtensions, (void **)&extensions,
                                     buffer + extensions_start, asn1_payload_size);
    if (rval.code != RC_OK) {
        dlog(DLOG_LEVEL_ERROR, "Decoding failed at byte %ld", rval.consumed);
        if (extensions) {
            ASN_STRUCT_FREE(asn_DEF_ESDPExtensions, extensions);
        }
        return 1;
    } else {
        dlog(DLOG_LEVEL_INFO, "Successfully decoded ESDPReq payload");
    }

    dec_std_ext_return = decode_esdp_extensions(extensions, sdp_query);

    if (dec_std_ext_return) {
        dlog(DLOG_LEVEL_ERROR, "Failed to decode ESDP extensions in ESDPReq payload");
        ASN_STRUCT_FREE(asn_DEF_ESDPExtensions, extensions);
        return 1;
    } else {
        dlog(DLOG_LEVEL_INFO, "Successfully decoded ESDP extensions in ESDPReq payload");
    }

    ASN_STRUCT_FREE(asn_DEF_ESDPExtensions, extensions);
    return 0;
}

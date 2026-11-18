// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
// Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
#ifndef ESDP_H
#define ESDP_H

#include "sdp.hpp"

#include <stdint.h>
#include <sys/types.h>

#define ESDP_SRV_PORT 15202

#define ESDP_V2GTP_HEADER_LEN          8
#define ESDP_SETUP_PAYLOAD_LEN         5
#define ESDP_MAX_V2GTP_MESSAGE_SIZE    0x1000
#define MAX_ESDP_REQUEST_PAYLOAD_LEN   (ESDP_MAX_V2GTP_MESSAGE_SIZE - ESDP_V2GTP_HEADER_LEN)

#define ESDP_SETUP_REQUEST_TYPE 0x2021
#define ESDP_REQUEST_TYPE       0x2023

#define ESDP_VERSION 0x0100

int esdp_validate_header(uint8_t* buffer, ssize_t recv_len, uint16_t expected_payload_type,
                         uint32_t max_esdp_payload_len, uint16_t expected_esdp_version,
                         uint32_t expected_payload_len);
int esdp_create_setup_response(uint8_t* buffer_esdp, uint16_t esdp_version);
int esdp_send_setup_response(int esdp_socket, struct sdp_query* sdp_query, uint16_t esdp_version);
int esdp_send_response(int esdp_socket, struct sdp_query* sdp_query);
int decode_esdp_payload(uint8_t* buffer, struct sdp_query* sdp_query, ssize_t recv_len);

#endif /* ESDP_H */

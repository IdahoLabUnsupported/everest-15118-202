// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
// Copyright 2026, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
#include <gtest/gtest.h>
#include <esdp.hpp>
#include <sdp.hpp>

namespace {

class SdpTest : public testing::Test {
protected:
    SdpTest() {
    }
};

TEST_F(SdpTest, sdp_write_header) {
    uint8_t buffer[20];
    uint16_t payload_type = 0x9001;
    uint32_t length = 367;

    EXPECT_EQ(sdp_write_header(buffer, payload_type, length), 8);

    EXPECT_EQ(buffer[0], 0x01);
    EXPECT_EQ(buffer[1], 0xFE);
    EXPECT_EQ(buffer[2], 0x90);
    EXPECT_EQ(buffer[3], 0x01);
    EXPECT_EQ(buffer[4], 0x00);
    EXPECT_EQ(buffer[5], 0x00);
    EXPECT_EQ(buffer[6], 0x01);
    EXPECT_EQ(buffer[7], 0x6F);
}

TEST_F(SdpTest, esdp_setup_response_advertises_secc_maximum_message_size) {
    uint8_t buffer[ESDP_SETUP_PAYLOAD_LEN + ESDP_V2GTP_HEADER_LEN] = {};

    EXPECT_EQ(esdp_create_setup_response(buffer, ESDP_VERSION), 13);
    EXPECT_EQ(MAX_ESDP_REQUEST_PAYLOAD_LEN + ESDP_V2GTP_HEADER_LEN,
              ESDP_MAX_V2GTP_MESSAGE_SIZE);
    EXPECT_EQ(buffer[0], 0x01);
    EXPECT_EQ(buffer[1], 0xFE);
    EXPECT_EQ(buffer[2], 0x20);
    EXPECT_EQ(buffer[3], 0x22);
    EXPECT_EQ(buffer[7], ESDP_SETUP_PAYLOAD_LEN);
    EXPECT_EQ(buffer[8], 0x01);
    EXPECT_EQ(buffer[9], 0x00);
    EXPECT_EQ(buffer[10], (ESDP_MAX_V2GTP_MESSAGE_SIZE >> 8) & 0xff);
    EXPECT_EQ(buffer[11], ESDP_MAX_V2GTP_MESSAGE_SIZE & 0xff);
    EXPECT_EQ(buffer[12], 0x00);
}

} // namespace

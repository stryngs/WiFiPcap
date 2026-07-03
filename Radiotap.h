#ifndef RADIOTAP_H
#define RADIOTAP_H

#include <stddef.h>
#include <stdint.h>

#ifndef STRUCT_PACKED
#define STRUCT_PACKED __attribute__((packed))
#endif

/*
  Radiotap fields are stored little-endian and must appear in increasing present
  bit order. Each field is aligned relative to the start of the radiotap header,
  not relative to the surrounding PCAP record.

  The first WiFiPcap pass intentionally uses only metadata the ESP32
  promiscuous RX callback exposes directly and reliably: flags, legacy rate,
  channel, RSSI, noise floor, and antenna.

  References:
    https://www.radiotap.org/
    Linux: include/net/ieee80211_radiotap.h
*/

constexpr uint8_t RADIOTAP_VERSION = 0;

enum RadiotapPresentBit : uint8_t {
    RADIOTAP_PRESENT_TSFT           = 0,
    RADIOTAP_PRESENT_FLAGS          = 1,
    RADIOTAP_PRESENT_RATE           = 2,
    RADIOTAP_PRESENT_CHANNEL        = 3,
    RADIOTAP_PRESENT_FHSS           = 4,
    RADIOTAP_PRESENT_DBM_ANTSIGNAL  = 5,
    RADIOTAP_PRESENT_DBM_ANTNOISE   = 6,
    RADIOTAP_PRESENT_LOCK_QUALITY   = 7,
    RADIOTAP_PRESENT_TX_ATTENUATION = 8,
    RADIOTAP_PRESENT_DB_TX_ATTENUATION = 9,
    RADIOTAP_PRESENT_DBM_TX_POWER   = 10,
    RADIOTAP_PRESENT_ANTENNA        = 11,
    RADIOTAP_PRESENT_DB_ANTSIGNAL   = 12,
    RADIOTAP_PRESENT_DB_ANTNOISE    = 13,
    RADIOTAP_PRESENT_RX_FLAGS       = 14,
    RADIOTAP_PRESENT_MCS            = 19,
    RADIOTAP_PRESENT_AMPDU_STATUS   = 20,
    RADIOTAP_PRESENT_VHT            = 21,
    RADIOTAP_PRESENT_TIMESTAMP      = 22,
    RADIOTAP_PRESENT_EXT            = 31
};

constexpr uint32_t radiotap_present_bit(RadiotapPresentBit bit) {
    return (1UL << bit);
}

enum RadiotapFlags : uint8_t {
    RADIOTAP_F_CFP       = 0x01,
    RADIOTAP_F_SHORTPRE  = 0x02,
    RADIOTAP_F_WEP       = 0x04,
    RADIOTAP_F_FRAG      = 0x08,
    RADIOTAP_F_FCS       = 0x10,
    RADIOTAP_F_DATAPAD   = 0x20,
    RADIOTAP_F_BADFCS    = 0x40,
    RADIOTAP_F_SHORTGI   = 0x80
};

enum RadiotapChannelFlags : uint16_t {
    RADIOTAP_CHAN_TURBO  = 0x0010,
    RADIOTAP_CHAN_CCK    = 0x0020,
    RADIOTAP_CHAN_OFDM   = 0x0040,
    RADIOTAP_CHAN_2GHZ   = 0x0080,
    RADIOTAP_CHAN_5GHZ   = 0x0100,
    RADIOTAP_CHAN_PASSIVE = 0x0200,
    RADIOTAP_CHAN_DYN    = 0x0400,
    RADIOTAP_CHAN_GFSK   = 0x0800,
    RADIOTAP_CHAN_GSM    = 0x1000,
    RADIOTAP_CHAN_STURBO = 0x2000,
    RADIOTAP_CHAN_HALF   = 0x4000,
    RADIOTAP_CHAN_QUARTER = 0x8000
};

enum RadiotapRxFlags : uint16_t {
    RADIOTAP_RX_F_BADPLCP = 0x0002
};

enum RadiotapMcsHave : uint8_t {
    RADIOTAP_MCS_HAVE_BW   = 0x01,
    RADIOTAP_MCS_HAVE_MCS  = 0x02,
    RADIOTAP_MCS_HAVE_GI   = 0x04,
    RADIOTAP_MCS_HAVE_FMT  = 0x08,
    RADIOTAP_MCS_HAVE_FEC  = 0x10,
    RADIOTAP_MCS_HAVE_STBC = 0x20
};

enum RadiotapMcsFlags : uint8_t {
    RADIOTAP_MCS_BW_20      = 0x00,
    RADIOTAP_MCS_BW_40      = 0x01,
    RADIOTAP_MCS_BW_20L     = 0x02,
    RADIOTAP_MCS_BW_20U     = 0x03,
    RADIOTAP_MCS_SGI        = 0x04,
    RADIOTAP_MCS_FMT_GF     = 0x08,
    RADIOTAP_MCS_FEC_LDPC   = 0x10,
    RADIOTAP_MCS_STBC_SHIFT = 5
};

struct RadiotapHeader {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present;
} STRUCT_PACKED;

struct RadiotapChannel {
    uint16_t frequency;
    uint16_t flags;
} STRUCT_PACKED;

struct RadiotapMcs {
    uint8_t known;
    uint8_t flags;
    uint8_t index;
} STRUCT_PACKED;

/*
  Fixed first-pass header layout:
    RadiotapHeader        offset 0,  size 8
    flags                 offset 8,  size 1
    rate                  offset 9,  size 1, 500 kb/s units
    channel               offset 10, size 4, 2-byte aligned
    dbm_antsignal         offset 14, size 1
    dbm_antnoise          offset 15, size 1
    antenna               offset 16, size 1

  No padding is required for this field set.
*/
struct RadiotapHeaderBasic {
    RadiotapHeader hdr;
    uint8_t flags;
    uint8_t rate;
    RadiotapChannel channel;
    int8_t dbm_antsignal;
    int8_t dbm_antnoise;
    uint8_t antenna;
} STRUCT_PACKED;

constexpr uint32_t RADIOTAP_BASIC_PRESENT =
    radiotap_present_bit(RADIOTAP_PRESENT_FLAGS) |
    radiotap_present_bit(RADIOTAP_PRESENT_RATE) |
    radiotap_present_bit(RADIOTAP_PRESENT_CHANNEL) |
    radiotap_present_bit(RADIOTAP_PRESENT_DBM_ANTSIGNAL) |
    radiotap_present_bit(RADIOTAP_PRESENT_DBM_ANTNOISE) |
    radiotap_present_bit(RADIOTAP_PRESENT_ANTENNA);

constexpr uint16_t RADIOTAP_BASIC_LENGTH = sizeof(RadiotapHeaderBasic);

static_assert(8u == sizeof(RadiotapHeader), "RadiotapHeader layout changed");
static_assert(10u == offsetof(RadiotapHeaderBasic, channel), "Radiotap channel alignment changed");
static_assert(17u == sizeof(RadiotapHeaderBasic), "RadiotapHeaderBasic layout changed");

constexpr uint16_t radiotap_channel_frequency_2ghz(uint8_t channel) {
    return (14 == channel) ? 2484u : (2407u + (uint16_t)channel * 5u);
}

constexpr uint16_t radiotap_channel_flags_2ghz(bool legacy_rate_cck) {
    return RADIOTAP_CHAN_2GHZ | (legacy_rate_cck ? RADIOTAP_CHAN_CCK : RADIOTAP_CHAN_OFDM);
}

#endif

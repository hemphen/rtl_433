/** @file
    Purmo / LVI Touch E3 electric radiators.

    Copyright (C) 2026 hemphen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "decoder.h"

/** @fn static int purmo_e3_decode(r_device *decoder, bitbuffer_t *bitbuffer)
Purmo / LVI Touch E3 controller and its electric radiators.

The Touch E3 panel (CleverTouch app) controls Purmo/LVI radiators such as
Yali Digital, Parada and Ramo over 868.3 MHz. Traffic runs both ways. It uses
the same envelope as the Watts Vision thermostat (see watts_vision.c, issue
#2885) with other message lengths; this decoder takes LEN 0x0d, 0x0f, 0x23 and
0x38 and leaves 0x14 and 0x22 to watts_vision, so the two never report one
frame twice. Use `-Y minmax`: with the classic FSK demodulator none of the
test recordings decoded.

Packet layout (all byte-aligned, after the AA D391 D391 sync):

    LEN:8h ID:32h MARKER:8h DEST:32h PAYLOAD:(LEN-11)*8h CRC_MDB:16h CRC_CMS:16h

- LEN: body length in bytes, ID through CRC_MDB; the frame is LEN + 3 bytes.
- ID: 32-bit source address. DEST: 32-bit destination address.
- MARKER: always 0xc6.
- PAYLOAD: ordinarily [tag][value] records whose value size is
  (tag >> 6) + 1 bytes; tag 0x00 ends them, followed only by zeros.
- CRC_MDB: CRC-16/MODBUS (reflected 0xa001, init 0xffff) over ID..PAYLOAD,
  little-endian.
- CRC_CMS: CRC-16/CMS (poly 0x8005, init 0xffff) over LEN..CRC_MDB, big-endian.

Message types come from whole payloads, never from addresses, and only the
observed shapes count: radiator_report (records DF 4B 8A E1 DA 0A) and
controller_state (45 4B 3B 4C 8E CC 97 94 E1 DA 5B B2), in that order and
unpadded; request (19 00), ack (01 00 0A 47), and the
inclusion exchange's offer (00 00 03 01 or 00 00 03 64, to a candidate
address), reply (00 00) and bind (01 00). Any other frame with valid CRCs is
reported as unknown with its bytes, and the reason when its payload is not a
record stream, but no roles or fields.

Records:

- 4B: measured air temperature.
- 8A (report) / 94 (state): target temperature and mode byte. Modes use the
  hemphen/clevertouch client's names, lowercase: 0 comfort, 1 off, 2 frost,
  3 eco, 4 boost, 8 and 11 program in its comfort and eco phase.
- E1: byte 1 the front-panel maximum power, percent; byte 2 duty as a share
  of rated power, byte 3 as a share of the limited power, so byte 2 has been
  byte 3 scaled by byte 1.
- DA: on-times in seconds, one for each duty.
- B2: the controller's clock, hours, minutes, seconds.
- 5B: Boost time in minutes, the duration the next Boost runs, or the time
  left while one runs; the panel holds and counts it.
- DF: byte 2 bit 0 set while the element is heating; byte 1 bit 0 set in the
  first report after a change made at the radiator; the word is kept raw.
- 97: the controller's echo of the radiator's DF, kept raw.
- 4C, 8E, CC (Tentative, the related Watts decoder's readings, never seen
  other than constant): 4C is a diagnostic code and warning flags, zero meaning
  no fault; 8E byte 2 bits 0-1 give the regulation sensor (ambient, floor,
  floor_limited, air), its bytes 0-1 are unknown; CC holds two floor
  temperature limits, tenths of a degree Fahrenheit, zero meaning inactive. All
  three are also kept raw.
- Others: kept raw, meaning unknown.

Temperatures are tenths of a degree Fahrenheit, 0x084c meaning unavailable,
and are reported in Fahrenheit as sent; -C si converts them to Celsius.
Duty and on-time are not calibrated against a power meter.
*/

static void purmo_hex(char *dst, uint8_t const *src, unsigned len)
{
    static char const digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < len; ++i) {
        dst[2 * i] = digits[src[i] >> 4];
        dst[2 * i + 1] = digits[src[i] & 15];
    }
    dst[2 * len] = '\0';
}

static int purmo_mode(uint8_t mode, char const **heat_mode, char const **temp_type)
{
    switch (mode) {
    case 0: *heat_mode = "comfort"; *temp_type = "comfort"; return 1;
    case 1: *heat_mode = "off"; *temp_type = "none"; return 1;
    case 2: *heat_mode = "frost"; *temp_type = "frost"; return 1;
    case 3: *heat_mode = "eco"; *temp_type = "eco"; return 1;
    case 4: *heat_mode = "boost"; *temp_type = "boost"; return 1;
    case 8: *heat_mode = "program"; *temp_type = "comfort"; return 1;
    case 11: *heat_mode = "program"; *temp_type = "eco"; return 1;
    default: return 0;
    }
}

static unsigned purmo_u16(uint8_t const *b)
{
    return ((unsigned)b[0] << 8) | b[1];
}

static uint8_t const purmo_report_tags[] = {0xdf, 0x4b, 0x8a, 0xe1, 0xda, 0x0a};
static uint8_t const purmo_state_tags[] = {0x45, 0x4b, 0x3b, 0x4c, 0x8e, 0xcc, 0x97, 0x94, 0xe1, 0xda, 0x5b, 0xb2};

// Payloads that are messages byte for byte; the offers and the reply lie
// outside the record grammar.
static struct {
    unsigned len;
    uint8_t payload[4];
    char const *msg;
    int radiator_source;
} const purmo_fixed[] = {
        {2, {0x19, 0x00}, "request", 0},
        {4, {0x01, 0x00, 0x0a, 0x47}, "ack", 1},
        {2, {0x01, 0x00}, "inclusion_bind", 0},
        {4, {0x00, 0x00, 0x03, 0x01}, "inclusion_offer", 0},
        {4, {0x00, 0x00, 0x03, 0x64}, "inclusion_offer", 0},
        {2, {0x00, 0x00}, "inclusion_reply", 1},
};

static int purmo_e3_packet(r_device *decoder, uint8_t const *b)
{
    unsigned len = b[0];
    if (b[5] != 0xc6)
        return DECODE_FAIL_SANITY;
    if (crc16lsb(b + 1, len - 2, 0xa001, 0xffff)
            != ((unsigned)b[len] << 8 | b[len - 1]))
        return DECODE_FAIL_MIC;
    if (crc16(b, len + 1, 0x8005, 0xffff) != purmo_u16(b + len + 1))
        return DECODE_FAIL_MIC;

    // Parse the record stream once before emitting anything. A payload the
    // grammar cannot parse is kept raw, with the reason, rather than rejected.
    unsigned end = len - 1;
    unsigned count = 0;
    int unpadded = 1;
    uint8_t tags[128];
    char error[48] = "";
    for (unsigned p = 10; p < end;) {
        uint8_t tag = b[p];
        if (!tag) {
            unpadded = 0;
            for (; p < end; ++p)
                if (b[p]) {
                    snprintf(error, sizeof(error), "nonzero bytes after record terminator");
                    break;
                }
            break;
        }
        unsigned size = (tag >> 6) + 1;
        if (p + 1 + size > end) {
            snprintf(error, sizeof(error), "record %02x overruns payload", tag);
            break;
        }
        if (count < sizeof(tags))
            tags[count] = tag;
        ++count;
        p += 1 + size;
    }

    char source[9], dest[9], raw[517], records[489];
    purmo_hex(source, b + 1, 4);
    purmo_hex(dest, b + 6, 4);
    purmo_hex(raw, b, len + 3);
    purmo_hex(records, b + 10, len - 11);
    // Only whole observed shapes are messages: a partial, extended or
    // repeated layout, or a short frame with other values, stays unknown.
    char const *msg = "unknown";
    int endpoint_source = -1;
    for (unsigned i = 0; i < sizeof(purmo_fixed) / sizeof(purmo_fixed[0]); ++i) {
        if (end - 10 == purmo_fixed[i].len && !memcmp(b + 10, purmo_fixed[i].payload, purmo_fixed[i].len)) {
            msg = purmo_fixed[i].msg;
            endpoint_source = purmo_fixed[i].radiator_source;
        }
    }
    if (endpoint_source < 0 && !*error && unpadded) {
        if (count == sizeof(purmo_report_tags) && !memcmp(tags, purmo_report_tags, count)) {
            msg = "radiator_report";
            endpoint_source = 1;
        }
        else if (count == sizeof(purmo_state_tags) && !memcmp(tags, purmo_state_tags, count)) {
            msg = "controller_state";
            endpoint_source = 0;
        }
    }
    int offer = !strcmp(msg, "inclusion_offer");
    int known = endpoint_source >= 0;
    if (offer)
        endpoint_source = -1;

    /* clang-format off */
    data_t *data = data_make(
            "model", "", DATA_STRING, "Purmo-E3",
            "id", "Source", DATA_STRING, source,
            "dest", "Destination", DATA_STRING, dest,
            "msg_type", "Message", DATA_STRING, msg,
            "length", "Body length", DATA_INT, len,
            "raw", "Packet", DATA_STRING, raw,
            "records_raw", "Records", DATA_STRING, records,
            NULL);
    /* clang-format on */
    if (offer) {
        // The destination is a discovery candidate, not an installed radiator.
        data = data_str(data, "controller_id", "", NULL, source);
        data = data_str(data, "candidate_id", "", NULL, dest);
        data = data_str(data, "payload_raw", "", NULL, records);
    }
    else if (*error) {
        data = data_str(data, "payload_raw", "", NULL, records);
        data = data_str(data, "payload_error", "", NULL, error);
    }
    if (endpoint_source >= 0) {
        data = data_str(data, "radiator_id", "", NULL, endpoint_source ? source : dest);
        data = data_str(data, "controller_id", "", NULL, endpoint_source ? dest : source);
    }
    // Fields only from a recognised message, whose layout has each tag once.
    for (unsigned p = 10; known && !*error && p < end && b[p];) {
        uint8_t tag = b[p];
        unsigned size = (tag >> 6) + 1;
        uint8_t const *v = b + p + 1;
        char hex[9];
        purmo_hex(hex, v, size);
        switch (tag) {
        case 0x4b:
            if (purmo_u16(v) != 0x084c)
                data = data_dbl(data, "temperature_F", "", "%.1f F", purmo_u16(v) / 10.0);
            break;
        case 0x8a:
        case 0x94: {
            if (purmo_u16(v) != 0x084c)
                data = data_dbl(data, "setpoint_F", "", "%.1f F", purmo_u16(v) / 10.0);
            char tag_str[3];
            snprintf(tag_str, sizeof(tag_str), "%02x", tag);
            data = data_str(data, "setpoint_tag", "", NULL, tag_str);
            data = data_int(data, "mode_raw", "", NULL, v[2]);
            char const *heat_mode, *temp_type;
            if (purmo_mode(v[2], &heat_mode, &temp_type)) {
                data = data_str(data, "heat_mode", "", NULL, heat_mode);
                data = data_str(data, "temp_type", "", NULL, temp_type);
            }
            break;
        }
        case 0xe1:
            data = data_str(data, "e1_raw", "", NULL, hex);
            data = data_int(data, "e1_0_raw", "", NULL, v[0]);
            data = data_int(data, "e1_1_raw", "", NULL, v[1]);
            if (v[1] <= 100)
                data = data_int(data, "max_power_pct", "", NULL, v[1]);
            if (v[2] <= 100 && v[3] <= 100) {
                data = data_int(data, "duty_1_pct", "", NULL, v[2]);
                data = data_int(data, "duty_2_pct", "", NULL, v[3]);
            }
            break;
        case 0xda:
            data = data_str(data, "da_raw", "", NULL, hex);
            data = data_int(data, "on_time_1_s", "", NULL, purmo_u16(v));
            data = data_int(data, "on_time_2_s", "", NULL, purmo_u16(v + 2));
            break;
        case 0xb2:
            data = data_str(data, "b2_raw", "", NULL, hex);
            if (v[0] < 24 && v[1] < 60 && v[2] < 60) {
                char clock[12];
                snprintf(clock, sizeof(clock), "%02u:%02u:%02u", v[0], v[1], v[2]);
                data = data_str(data, "clock", "", NULL, clock);
            }
            break;
        case 0x5b:
            data = data_int(data, "boost_time_min", "", NULL, purmo_u16(v));
            break;
        case 0xdf:
            data = data_str(data, "state_df_raw", "", NULL, hex);
            data = data_int(data, "heating", "", NULL, v[2] & 1);
            data = data_int(data, "changed_at_radiator", "", NULL, v[1] & 1);
            break;
        case 0x97:
            data = data_str(data, "state_97_raw", "", NULL, hex);
            break;
        default:
            // Preserve known opaque values as individual fields, unknowns in raw.
            if (tag == 0x45 || tag == 0x3b || tag == 0x4c || tag == 0x8e
                    || tag == 0xcc || tag == 0x0a || tag == 0x01 || tag == 0x19) {
                char key[16];
                snprintf(key, sizeof(key), "tag_%02x_raw", tag);
                data = data_str(data, key, "", NULL, hex);
            }
            // Tentative readings of the related Watts decoder.
            if (tag == 0x4c) {
                data = data_int(data, "diagnostic_code", "", NULL, v[0]);
                data = data_int(data, "diagnostic_flags", "", NULL, v[1]);
            }
            else if (tag == 0x8e) {
                static char const *const sensors[] = {"ambient", "floor", "floor_limited", "air"};
                data = data_str(data, "regulation_sensor", "", NULL, sensors[v[2] & 3]);
            }
            else if (tag == 0xcc) {
                // Zero is an inactive limit; 0x084c is the unavailable value.
                for (unsigned n = 0; n < 2; ++n) {
                    unsigned limit = purmo_u16(v + 2 * n);
                    char limit_key[16];
                    snprintf(limit_key, sizeof(limit_key), "floor_limit_%u_F", n + 1);
                    if (limit && limit != 0x084c)
                        data = data_dbl(data, limit_key, "", "%.1f F", limit / 10.0);
                }
            }
            break;
        }
        p += 1 + size;
    }
    data = data_str(data, "mic", "Integrity", NULL, "CRC");
    decoder_output_data(decoder, data);
    return 1;
}

static int purmo_e3_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
    uint8_t const sync[] = {0xaa, 0xd3, 0x91, 0xd3, 0x91};
    int successes = 0, last_error = DECODE_ABORT_EARLY;
    for (unsigned row = 0; row < bitbuffer->num_rows; ++row) {
        unsigned row_bits = bitbuffer->bits_per_row[row];
        unsigned search = 0;
        while (search < row_bits) {
            unsigned start = bitbuffer_search(bitbuffer, row, search, sync, 40);
            if (start >= row_bits)
                break;
            unsigned payload = start + 40;
            search = payload;
            if (payload + 8 > row_bits) {
                last_error = DECODE_ABORT_LENGTH;
                continue;
            }
            uint8_t len_byte;
            bitbuffer_extract_bytes(bitbuffer, row, payload, &len_byte, 8);
            // Exclude Watts Vision's existing 14/22 messages to avoid duplicates.
            if (len_byte != 0x0d && len_byte != 0x0f && len_byte != 0x23 && len_byte != 0x38)
                continue;
            unsigned packet_bits = ((unsigned)len_byte + 3) * 8;
            if (packet_bits > row_bits - payload) {
                last_error = DECODE_ABORT_LENGTH;
                continue;
            }
            uint8_t packet[258] = {0};
            bitbuffer_extract_bytes(bitbuffer, row, payload, packet, packet_bits);
            int result = purmo_e3_packet(decoder, packet);
            if (result > 0) {
                successes += result;
                search = payload + packet_bits;
            }
            else {
                last_error = result;
            }
        }
    }
    return successes ? successes : last_error;
}

static char const *const output_fields[] = {
        "model", "id", "dest", "radiator_id", "controller_id", "candidate_id",
        "msg_type", "length", "raw", "records_raw", "payload_raw", "payload_error",
        "temperature_F", "setpoint_F", "setpoint_tag", "mode_raw", "heat_mode",
        "temp_type", "e1_raw", "e1_0_raw", "e1_1_raw", "max_power_pct",
        "duty_1_pct", "duty_2_pct", "da_raw",
        "on_time_1_s", "on_time_2_s", "b2_raw",
        "clock", "boost_time_min", "state_df_raw", "heating", "changed_at_radiator",
        "state_97_raw", "diagnostic_code", "diagnostic_flags", "regulation_sensor",
        "floor_limit_1_F", "floor_limit_2_F", "tag_45_raw", "tag_3b_raw", "tag_4c_raw", "tag_8e_raw", "tag_cc_raw",
        "tag_0a_raw", "tag_01_raw", "tag_19_raw", "mic", NULL,
};

r_device const purmo_e3 = {
        .name        = "Purmo / LVI Touch E3 electric radiators (-f 868.3M)",
        .modulation  = FSK_PULSE_PCM,
        .short_width = 27,
        .long_width  = 27,
        .reset_limit = 1000,
        .decode_fn   = &purmo_e3_decode,
        .fields      = output_fields,
};

#include "mx_lookup.h"

#include <stdlib.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static int compare_mx_records(const void *left, const void *right) {
    const MxRecord *left_record = left;
    const MxRecord *right_record = right;

    if (left_record->preference < right_record->preference) {
        return -1;
    }
    if (left_record->preference > right_record->preference) {
        return 1;
    }
    return strcmp(left_record->exchange, right_record->exchange);
}

static int skip_name(const uint8_t *packet, size_t packet_length, size_t *offset) {
    size_t position = *offset;
    size_t labels = 0;
    int followed_pointer = 0;

    while (position < packet_length) {
        uint8_t length = packet[position++];

        if (length == 0) {
            if (!followed_pointer) {
                *offset = position;
            }
            return 0;
        }
        if ((length & 0xC0) == 0xC0) {
            uint16_t pointer;

            if (position >= packet_length) {
                return -1;
            }
            pointer = (uint16_t)(((length & 0x3F) << 8) | packet[position]);
            if (pointer >= packet_length || ++labels > DNS_MAX_NAME) {
                return -1;
            }
            if (!followed_pointer) {
                *offset = position + 1;
                followed_pointer = 1;
            }
            position = pointer;
            continue;
        }
        if ((length & 0xC0) != 0 || length > DNS_MAX_LABEL ||
            packet_length - position < length || ++labels > DNS_MAX_NAME) {
            return -1;
        }
        position += length;
    }

    return -1;
}

static int read_name(
    const uint8_t *packet,
    size_t packet_length,
    size_t offset,
    size_t inline_end,
    char *name,
    size_t name_capacity
) {
    size_t position = offset;
    size_t output_length = 0;
    size_t jumps = 0;
    int followed_pointer = 0;

    while (position < packet_length) {
        if (!followed_pointer && position >= inline_end) {
            return -1;
        }
        uint8_t length = packet[position++];

        if (length == 0) {
            if (output_length == 0) {
                return -1;
            }
            name[output_length] = '\0';
            return 0;
        }
        if ((length & 0xC0) == 0xC0) {
            uint16_t pointer;

            if (position >= packet_length) {
                return -1;
            }
            pointer = (uint16_t)(((length & 0x3F) << 8) | packet[position]);
            if (pointer >= packet_length || ++jumps > DNS_MAX_NAME) {
                return -1;
            }
            position = pointer;
            followed_pointer = 1;
            continue;
        }
        if ((length & 0xC0) != 0 || length > DNS_MAX_LABEL ||
            packet_length - position < length ||
            output_length + length + (output_length != 0 ? 1 : 0) >= name_capacity) {
            return -1;
        }
        if (output_length != 0) {
            name[output_length++] = '.';
        }
        memcpy(&name[output_length], &packet[position], length);
        output_length += length;
        position += length;
    }

    return -1;
}

DnsMxResult dns_parse_mx_response(
    const uint8_t *response,
    size_t response_length,
    uint16_t transaction_id,
    MxRecord *records,
    size_t records_capacity,
    size_t *record_count
) {
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t rcode;
    size_t offset = DNS_HEADER_SIZE;
    uint16_t index;

    if (response == NULL || record_count == NULL ||
        (records == NULL && records_capacity != 0) ||
        response_length < DNS_HEADER_SIZE) {
        return DNS_MX_INVALID_RESPONSE;
    }
    *record_count = 0;
    if (read_u16(response) != transaction_id) {
        return DNS_MX_INVALID_RESPONSE;
    }

    flags = read_u16(&response[2]);
    if ((flags & 0x8000) == 0) {
        return DNS_MX_INVALID_RESPONSE;
    }
    rcode = (uint16_t)(flags & 0x000F);

    question_count = read_u16(&response[4]);
    answer_count = read_u16(&response[6]);
    if (question_count == 0) {
        return DNS_MX_INVALID_RESPONSE;
    }

    for (index = 0; index < question_count; ++index) {
        if (skip_name(response, response_length, &offset) != 0 ||
            response_length - offset < 4) {
            return DNS_MX_INVALID_RESPONSE;
        }
        offset += 4;
    }

    for (index = 0; index < answer_count; ++index) {
        uint16_t type;
        uint16_t class;
        uint16_t data_length;
        size_t data_offset;

        if (skip_name(response, response_length, &offset) != 0 ||
            response_length - offset < 10) {
            return DNS_MX_INVALID_RESPONSE;
        }
        type = read_u16(&response[offset]);
        class = read_u16(&response[offset + 2]);
        data_length = read_u16(&response[offset + 8]);
        offset += 10;
        if (response_length - offset < data_length) {
            return DNS_MX_INVALID_RESPONSE;
        }

        data_offset = offset;
        if (type == DNS_TYPE_MX && class == DNS_CLASS_IN) {
            char exchange[DNS_MAX_NAME + 1];

            if (data_length < 3 ||
                read_name(response, response_length, data_offset + 2,
                          data_offset + data_length, exchange,
                          sizeof(exchange)) != 0) {
                return DNS_MX_INVALID_RESPONSE;
            }
            if (rcode == 0) {
                if (records == NULL || *record_count >= records_capacity) {
                    return DNS_MX_INVALID_RESPONSE;
                }
                records[*record_count].preference = read_u16(&response[data_offset]);
                memcpy(records[*record_count].exchange, exchange, sizeof(exchange));
                ++(*record_count);
            }
        }
        offset += data_length;
    }

    if (rcode == 3) {
        return DNS_MX_NXDOMAIN;
    }
    if (rcode != 0) {
        return DNS_MX_INVALID_RESPONSE;
    }

    if (*record_count == 0) {
        return DNS_MX_NOT_FOUND;
    }

    qsort(records, *record_count, sizeof(records[0]), compare_mx_records);
    return DNS_MX_FOUND;
}
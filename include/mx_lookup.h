#ifndef MX_LOOKUP_H
#define MX_LOOKUP_H

#include <stddef.h>
#include <stdint.h>

#include "dns_types.h"

typedef enum {
    DNS_MX_FOUND = 0,
    DNS_MX_NOT_FOUND = 1,
    DNS_MX_NXDOMAIN = 2,
    DNS_MX_INVALID_RESPONSE = 3
} DnsMxResult;

/*
 * Classifica uma resposta DNS e copia os registros MX encontrados.
 * A resposta deve conter uma resposta para transaction_id.
 */
DnsMxResult dns_parse_mx_response(
    const uint8_t *response,
    size_t response_length,
    uint16_t transaction_id,
    MxRecord *records,
    size_t records_capacity,
    size_t *record_count
);

#endif
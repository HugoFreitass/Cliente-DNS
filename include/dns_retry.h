#ifndef DNS_RETRY_H
#define DNS_RETRY_H

#include <stddef.h>
#include <stdint.h>

#define DNS_MAX_ATTEMPTS 3
#define DNS_TIMEOUT_SECONDS 2

#define DNS_RETRY_OK 0
#define DNS_RETRY_ERROR -1
#define DNS_RETRY_EXHAUSTED 1

int dns_query_with_retries(
    const char *server_ip,
    uint16_t server_port,
    const uint8_t *query,
    size_t query_length,
    uint16_t transaction_id,
    uint8_t *response,
    size_t response_size,
    size_t *response_length
);

#endif
#include "dns_retry.h"

#include "dns_client.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

static int dns_response_has_transaction_id(
    const uint8_t *response,
    size_t response_length,
    uint16_t expected_transaction_id
) {
    uint16_t received_transaction_id;

    if (response == NULL || response_length < 2) {
        return 0;
    }

    received_transaction_id = (uint16_t)(
        ((uint16_t)response[0] << 8) |
        (uint16_t)response[1]
    );

    return received_transaction_id == expected_transaction_id;
}

int dns_query_with_retries(
    const char *server_ip,
    uint16_t server_port,
    const uint8_t *query,
    size_t query_length,
    uint16_t transaction_id,
    uint8_t *response,
    size_t response_size,
    size_t *response_length
) {
    int attempt;
    int client_result;
    size_t received_length;

    if (server_ip == NULL ||
        query == NULL ||
        response == NULL ||
        response_length == NULL ||
        query_length == 0 ||
        response_size == 0) {
        return DNS_RETRY_ERROR;
    }

    *response_length = 0;

    for (attempt = 1; attempt <= DNS_MAX_ATTEMPTS; ++attempt) {
        received_length = 0;

        client_result = dns_client_query(
            server_ip,
            server_port,
            query,
            query_length,
            response,
            response_size,
            &received_length,
            DNS_TIMEOUT_SECONDS
        );

        if (client_result == DNS_CLIENT_TIMEOUT) {
            continue;
        }

        if (client_result != DNS_CLIENT_OK) {
            return DNS_RETRY_ERROR;
        }

        if (!dns_response_has_transaction_id(
                response,
                received_length,
                transaction_id
            )) {
            /*
             * Recebeu um pacote, mas ele não pertence à consulta atual
             * ou é pequeno demais para um cabeçalho DNS válido.
             * Consome esta tentativa e tenta de novo.
             */
            continue;
        }

        *response_length = received_length;

        return DNS_RETRY_OK;
    }

    return DNS_RETRY_EXHAUSTED;
}
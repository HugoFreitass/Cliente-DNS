#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#define DNS_CLIENT_OK 0
#define DNS_CLIENT_ERROR -1
#define DNS_CLIENT_TIMEOUT 1
#define DNS_CLIENT_INVALID_RESPONSE 2
#define DNS_CLIENT_TIMEOUT_SECONDS 2

int dns_client_query(
    const char *server_ip, // IP do DNS
    uint16_t server_port, // porta
    const uint8_t *query, // bytes de consulta DNS
    size_t query_length, // quantidade de bytes da consulta
    uint8_t *response, // buffer onde a resposta será armanezada
    size_t response_size, // capacidade do bufer de resposta
    size_t *response_length, // quantidade efetivamente recebida
    int timeout_seconds // tempo máximo de espera
);

int dns_client_query_retry(
    const char *server_ip,
    uint16_t server_port,
    const uint8_t *query,
    size_t query_length,
    uint8_t *response,
    size_t response_size,
    size_t *response_length,
    unsigned int attempts
);

#endif
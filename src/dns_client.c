#include "dns_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int dns_client_query_attempt(
    const char *server_ip,
    uint16_t server_port,
    const uint8_t *query,
    size_t query_length,
    uint8_t *response,
    size_t response_size,
    size_t *response_length,
    int timeout_seconds
) {
    int socket_fd;
    int result;
    ssize_t sent_bytes;
    ssize_t received_bytes;
    struct sockaddr_in server_address;
    struct timeval timeout;

    if (server_ip == NULL ||
        query == NULL ||
        response == NULL ||
        response_length == NULL ||
        query_length == 0 ||
        response_size == 0 ||
        timeout_seconds != DNS_CLIENT_TIMEOUT_SECONDS) {
        return DNS_CLIENT_ERROR;
    }

    *response_length = 0;

    socket_fd = socket(
        AF_INET,
        SOCK_DGRAM,
        0
    );

    if (socket_fd < 0) {
        perror("socket");
        return DNS_CLIENT_ERROR;
    }

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);

    result = inet_pton(
        AF_INET,
        server_ip,
        &server_address.sin_addr
    );

    if (result == 0) {
        fprintf(
            stderr,
            "Erro: endereco IPv4 invalido: %s\n",
            server_ip
        );

        close(socket_fd);
        return DNS_CLIENT_ERROR;
    }

    if (result < 0) {
        perror("inet_pton");
        close(socket_fd);
        return DNS_CLIENT_ERROR;
    }

    timeout.tv_sec = DNS_CLIENT_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    result = setsockopt(
        socket_fd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
    );

    if (result < 0) {
        perror("setsockopt");
        close(socket_fd);
        return DNS_CLIENT_ERROR;
    }

    sent_bytes = sendto(
        socket_fd,
        query,
        query_length,
        0,
        (struct sockaddr *)&server_address,
        sizeof(server_address)
    );

    if (sent_bytes < 0) {
        perror("sendto");
        close(socket_fd);
        return DNS_CLIENT_ERROR;
    }

    if ((size_t)sent_bytes != query_length) {
        fprintf(
            stderr,
            "Erro: envio incompleto da consulta DNS\n"
        );

        close(socket_fd);
        return DNS_CLIENT_ERROR;
    }

    received_bytes = recvfrom(
        socket_fd,
        response,
        response_size,
        0,
        NULL,
        NULL
    );

    if (received_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            close(socket_fd);
            return DNS_CLIENT_TIMEOUT;
        }

        perror("recvfrom");
        close(socket_fd);
        return DNS_CLIENT_ERROR;
    }

    if (received_bytes < 12) {
        close(socket_fd);
        return DNS_CLIENT_INVALID_RESPONSE;
    }

    *response_length = (size_t)received_bytes;

    close(socket_fd);

    return DNS_CLIENT_OK;
}

int dns_client_query(
    const char *server_ip,
    uint16_t server_port,
    const uint8_t *query,
    size_t query_length,
    uint8_t *response,
    size_t response_size,
    size_t *response_length,
    int timeout_seconds
) {
    return dns_client_query_attempt(
        server_ip,
        server_port,
        query,
        query_length,
        response,
        response_size,
        response_length,
        timeout_seconds
    );
}

int dns_client_query_retry(
    const char *server_ip,
    uint16_t server_port,
    const uint8_t *query,
    size_t query_length,
    uint8_t *response,
    size_t response_size,
    size_t *response_length,
    unsigned int attempts
) {
    unsigned int attempt;
    int result;

    if (attempts == 0) {
        return DNS_CLIENT_ERROR;
    }

    for (attempt = 0; attempt < attempts; ++attempt) {
        result = dns_client_query_attempt(
            server_ip,
            server_port,
            query,
            query_length,
            response,
            response_size,
            response_length,
            DNS_CLIENT_TIMEOUT_SECONDS
        );

        if (result != DNS_CLIENT_TIMEOUT) {
            return result;
        }
    }

    return DNS_CLIENT_TIMEOUT;
}
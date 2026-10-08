#include "dns_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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
        timeout_seconds < 0) {
        return -1;
    }

    *response_length = 0;

    // Cria socket
    socket_fd = socket(
        AF_INET, // IPv4
        SOCK_DGRAM, // UDP
        0 // protocolo padrão correspondente ao tipo
    );

    if (socket_fd < 0) {
        perror("socket");
        return -1;
    }

    // setta uma valor na memória
    memset(
        &server_address, // ponto inicial na memória
        0, // valor que usado para preencher
        sizeof(server_address) // até onde irá na memória
    );

    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_port = htons(server_port); //

    result = inet_pton(
        AF_INET,
        server_ip,
        &server_address.sin_addr
    );

    if (result != 1) {
        if (result == 0) {
            fprintf(
                stderr,
                "Erro: endereco IPv4 invalido: %s\n",
                server_ip
            );
        } else {
            perror("inet_pton");
        }

        close(socket_fd);
        return -1;
    }

    timeout.tv_sec = timeout_seconds;
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
        return -1;
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
        return -1;
    }

    if ((size_t)sent_bytes != query_length) {
        fprintf(
            stderr,
            "Erro: quantidade de bytes enviada foi incompleta\n"
        );

        close(socket_fd);
        return -1;
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
            fprintf(
                stderr,
                "Erro: tempo limite de recebimento excedido\n"
            );
        } else {
            perror("recvfrom");
        }

        close(socket_fd);
        return -1;
    }

    *response_length = (size_t)received_bytes;

    close(socket_fd);

    return 0;
}
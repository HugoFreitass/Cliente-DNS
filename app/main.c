#include "cli.h"
#include "dns_retry.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DNS_PORT 53
#define DNS_RESPONSE_MAX_SIZE 512

int main(int argc, char *argv[]) {
    CliArguments arguments;
    const uint8_t query[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,

        0x00, 0x0F,
        0x00, 0x01
    };
    uint8_t response[DNS_RESPONSE_MAX_SIZE];
    size_t response_length;
    int result;

    if (cli_parse_arguments(argc, argv, &arguments) != 0) {
        cli_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    result = dns_query_with_retries(
        argv[2],
        DNS_PORT,
        query,
        sizeof(query),
        0x1234,
        response,
        sizeof(response),
        &response_length
    );

    if (result == DNS_RETRY_EXHAUSTED) {
        printf(
            "Nao foi possivel coletar entrada MX para %s\n",
            arguments.domain
        );

        return EXIT_FAILURE;
    }

    if (result == DNS_RETRY_ERROR) {
        fprintf(
            stderr,
            "Erro ao consultar o servidor DNS.\n"
        );

        return EXIT_FAILURE;
    }

    printf(
        "Resposta DNS recebida: %zu bytes\n",
        response_length
    );

    return EXIT_SUCCESS;
}
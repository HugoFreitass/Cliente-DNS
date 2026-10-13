#include "cli.h"
#include "dns_packet.h"
#include "dns_retry.h"
#include "dns_types.h"
#include "mx_lookup.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    CliArguments arguments;
    uint8_t query[DNS_MAX_PACKET_SIZE];
    uint8_t response[DNS_MAX_PACKET_SIZE];
    MxRecord records[DNS_MAX_PACKET_SIZE / 16];
    size_t query_length;
    size_t response_length;
    size_t record_count;
    DnsMxResult mx_result;
    int result;

    if (cli_parse_arguments(argc, argv, &arguments) != 0) {
        cli_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (dns_build_mx_query(
            query,
            sizeof(query),
            &query_length,
            0x1234,
            arguments.domain
        ) != 0) {
        fprintf(stderr, "Dominio invalido: %s\n", arguments.domain);
        return EXIT_FAILURE;
    }

    result = dns_query_with_retries(
        argv[2],
        DNS_PORT,
        query,
        query_length,
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

    mx_result = dns_parse_mx_response(
        response,
        response_length,
        0x1234,
        records,
        sizeof(records) / sizeof(records[0]),
        &record_count
    );

    if (mx_result == DNS_MX_NXDOMAIN) {
        printf("Dominio %s nao encontrado\n", arguments.domain);
        return EXIT_SUCCESS;
    }
    if (mx_result == DNS_MX_NOT_FOUND) {
        printf("Dominio %s nao possui entrada MX\n", arguments.domain);
        return EXIT_SUCCESS;
    }
    if (mx_result != DNS_MX_FOUND) {
        fprintf(stderr, "Resposta DNS invalida para %s\n", arguments.domain);
        return EXIT_FAILURE;
    }

    for (size_t index = 0; index < record_count; ++index) {
        printf(
            "MX %s %u %s\n",
            arguments.domain,
            records[index].preference,
            records[index].exchange
        );
    }

    return EXIT_SUCCESS;
}
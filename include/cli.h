#ifndef CLI_H
#define CLI_H

#include <netinet/in.h>

typedef struct {
    const char *domain;
    struct in_addr dns_server;
} CliArguments;

int cli_parse_arguments(int argc, char *argv[], CliArguments *arguments);

void cli_print_usage(const char *program_name);

#endif

// struct in_addr {
//     in_addr_t s_addr; // Endereço IP IPv4 de 32 bits
// };

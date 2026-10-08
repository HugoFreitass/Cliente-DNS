#include "cli.h"

#include <arpa/inet.h>
#include <stdio.h>

void cli_print_usage(const char *program_name){
    fprintf(stderr, "Uso: %s <nome_dominio> <ip_servidor_dns>\n", program_name);
    // fprintf(fluxo, formato, argumentos)
}

int cli_parse_arguments(int argc, char *argv[], CliArguments *arguments){
    // argc -> Argument Count; argv -> Argument Vector;
    int conversion_result;
    if (!argv || !arguments || argc !=3){
        return -1;
    }

    if(argv[1][0] == '\0' || argv[2][0] == '\0'){
        return -1;
    }

    // Internet Presentation to Network
    conversion_result = inet_pton(AF_INET, // Familia do protocolo (IPv4)
        argv[2], // DNS
        &arguments->dns_server // Apresentação do ip texto para binário
        );

    if(conversion_result != 1){
        return -1;
    }

    arguments -> domain = argv[1];

    return 0;
}
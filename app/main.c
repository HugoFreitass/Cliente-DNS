#include "cli.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    CliArguments arguments;

    if(cli_parse_arguments(argc, argv, &arguments) != 0) {
        cli_print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    printf("Dominio recebido: %s\n", arguments.domain);

    return EXIT_SUCCESS;
}
#ifndef DNS_NAME_H
#define DNS_NAME_H

#include <stddef.h>
#include <stdint.h>

/*
 * Codifica um dominio textual no formato QNAME a partir de buffer[*offset].
 * Exemplo: "example.com" -> 07 example 03 com 00.
 * Um ponto final opcional e aceito ("example.com." equivale a "example.com").
 * Em caso de sucesso, avanca *offset para depois do byte 0 final e retorna 0.
 * Em caso de erro, retorna -1 e nao altera *offset.
 */
int dns_encode_name(
    uint8_t *buffer,
    size_t buffer_size,
    size_t *offset,
    const char *name
);

#endif

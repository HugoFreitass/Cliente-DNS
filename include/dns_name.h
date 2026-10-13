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

/* Mascara dos dois bits mais significativos que identificam um ponteiro (11xxxxxx). */
#define DNS_POINTER_MASK 0xC0

/* Quantidade maxima de ponteiros seguidos ao decodificar um nome. */
#define DNS_MAX_POINTER_JUMPS 32

/*
 * Decodifica o nome que comeca em packet[*offset] para o formato textual.
 * Exemplo: 03 www 07 example 03 com 00 -> "www.example.com".
 *
 * Suporta name compression (RFC 1035, secao 4.1.4): ao encontrar um ponteiro,
 * continua a leitura no offset apontado, limitado a DNS_MAX_POINTER_JUMPS
 * saltos para evitar loops. O nome raiz (byte 0 isolado) gera "".
 *
 * Em caso de sucesso, avanca *offset para logo depois do nome na posicao
 * original (depois do byte 0 ou do primeiro ponteiro) e retorna 0.
 * Retorna -1, sem alterar *offset, se o pacote estiver truncado, um ponteiro
 * for invalido ou circular, uma etiqueta for invalida ou output for pequeno.
 */
int dns_decode_name(
    const uint8_t *packet,
    size_t packet_size,
    size_t *offset,
    char *output,
    size_t output_size
);

#endif

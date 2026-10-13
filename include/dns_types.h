#ifndef DNS_TYPES_H
#define DNS_TYPES_H

#include <stdint.h>

/* Porta UDP padrao do servico DNS (RFC 1035, secao 4.2.1). */
#define DNS_PORT 53

/* Tamanho maximo de uma mensagem DNS sobre UDP (RFC 1035, secao 2.3.4). */
#define DNS_MAX_PACKET_SIZE 512

/* Tamanho fixo do cabecalho DNS, em bytes. */
#define DNS_HEADER_SIZE 12

/* Tamanho maximo de um nome DNS, em bytes (RFC 1035, secao 2.3.4). */
#define DNS_MAX_NAME 255

/* Tamanho maximo de uma etiqueta (label) DNS, em bytes. */
#define DNS_MAX_LABEL 63

/* Flags de uma consulta padrao com recursao desejada (RD = 1). */
#define DNS_FLAGS_STANDARD_QUERY 0x0100

/* Mascaras do campo FLAGS do cabecalho (RFC 1035, secao 4.1.1). */
#define DNS_FLAG_QR 0x8000     /* 1 = resposta, 0 = consulta */
#define DNS_FLAG_TC 0x0200     /* mensagem truncada */
#define DNS_RCODE_MASK 0x000F  /* codigo de resposta (4 bits menos significativos) */

/* Valores de RCODE (RFC 1035, secao 4.1.1). */
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5

/* TYPE MX: mail exchange (RFC 1035, secao 3.2.2). */
#define DNS_TYPE_MX 15

/* CLASS IN: Internet (RFC 1035, secao 3.2.4). */
#define DNS_CLASS_IN 1

/* Quantidade maxima de tentativas de envio da consulta. */
#define DNS_MAX_ATTEMPTS 3

/* Tempo de espera por resposta em cada tentativa, em segundos. */
#define DNS_TIMEOUT_SECONDS 2

/*
 * Capacidade sugerida para o vetor de registros MX. Cada registro MX ocupa ao
 * menos 16 bytes na resposta, entao um pacote de 512 bytes contem no maximo ~30.
 */
#define DNS_MAX_MX_RECORDS 32

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
} DnsHeader;

typedef struct {
    char name[DNS_MAX_NAME + 1];
    uint16_t qtype;
    uint16_t qclass;
} DnsQuestion;

typedef struct {
    uint16_t preference;
    char exchange[DNS_MAX_NAME + 1];
} MxRecord;

#endif

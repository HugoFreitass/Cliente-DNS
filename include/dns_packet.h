#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <stddef.h>
#include <stdint.h>

/* Tamanho dos campos QTYPE + QCLASS que seguem o QNAME na pergunta. */
#define DNS_QUESTION_FIXED_SIZE 4

/*
 * Monta em packet o payload de uma consulta DNS do tipo MX/IN para domain.
 *
 * Cabecalho: ID = transaction_id, FLAGS = 0x0100, QDCOUNT = 1,
 * ANCOUNT = NSCOUNT = ARCOUNT = 0. Todos os campos em network byte order.
 *
 * Em caso de sucesso, grava o tamanho do payload em *packet_length e retorna 0.
 * Retorna -1 se algum ponteiro for nulo, o dominio for invalido ou o buffer
 * for insuficiente. O pacote apenas e montado; nao e enviado pela rede.
 */
int dns_build_mx_query(
    uint8_t *packet,
    size_t packet_size,
    size_t *packet_length,
    uint16_t transaction_id,
    const char *domain
);

#endif

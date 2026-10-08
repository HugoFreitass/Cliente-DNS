#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include "dns_types.h"

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

/*
 * Gera um transaction ID aleatorio de 16 bits e o grava em *transaction_id.
 *
 * Estrategia: le 2 bytes de /dev/urandom (fonte de entropia do kernel Linux).
 * Se /dev/urandom nao estiver disponivel, usa rand() semeado uma unica vez
 * com time() e clock(), combinando duas chamadas para cobrir os 16 bits.
 *
 * O chamador deve guardar o ID gerado para validar a resposta.
 * Retorna 0 em caso de sucesso ou -1 se transaction_id for nulo.
 */
int dns_generate_transaction_id(uint16_t *transaction_id);

/*
 * Le o transaction ID dos dois primeiros bytes de packet (network byte order).
 * Retorna 0 em caso de sucesso ou -1 se o pacote tiver menos de 2 bytes.
 */
int dns_read_transaction_id(
    const uint8_t *packet,
    size_t packet_size,
    uint16_t *transaction_id
);

/*
 * Confere se o transaction ID da resposta e igual ao ID enviado na consulta.
 * Retorna 0 se forem iguais ou -1 se divergirem ou a resposta for invalida.
 */
int dns_validate_transaction_id(
    const uint8_t *response,
    size_t response_length,
    uint16_t expected_id
);

/*
 * Le os 12 bytes do cabecalho de uma resposta DNS e grava em *header os campos
 * ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT e ARCOUNT em host byte order.
 *
 * Retorna -1 se algum ponteiro for nulo, se o pacote tiver menos de 12 bytes
 * ou se o bit QR for 0 (a mensagem e uma consulta, nao uma resposta).
 * O transaction ID e conferido por dns_validate_transaction_id().
 */
int dns_parse_header(
    const uint8_t *packet,
    size_t packet_size,
    DnsHeader *header
);

/* Retorna 1 se o bit QR indicar resposta, 0 caso contrario. */
int dns_header_is_response(const DnsHeader *header);

/* Retorna 1 se o bit TC indicar resposta truncada, 0 caso contrario. */
int dns_header_is_truncated(const DnsHeader *header);

/* Retorna o RCODE (0 a 15) do cabecalho. */
uint8_t dns_header_rcode(const DnsHeader *header);

/*
 * Le uma pergunta (QNAME, QTYPE, QCLASS) a partir de packet[*offset].
 * QNAME pode usar name compression. QTYPE e QCLASS sao convertidos para
 * host byte order.
 *
 * Em caso de sucesso, avanca *offset para depois de QCLASS e retorna 0.
 * Retorna -1, sem alterar *offset, se o pacote estiver truncado ou o QNAME
 * for invalido.
 */
int dns_parse_question(
    const uint8_t *packet,
    size_t packet_size,
    size_t *offset,
    DnsQuestion *question
);

/*
 * Le as question_count perguntas (QDCOUNT) que comecam em packet[*offset],
 * normalmente DNS_HEADER_SIZE, e confirma que todas sao do tipo MX e classe IN.
 *
 * Em caso de sucesso, deixa *offset apontando para o inicio da secao Answer e
 * retorna 0. Retorna -1, sem alterar *offset, se o pacote nao contiver todas
 * as perguntas indicadas ou alguma nao for MX/IN.
 */
int dns_parse_questions(
    const uint8_t *packet,
    size_t packet_size,
    uint16_t question_count,
    size_t *offset
);

#endif

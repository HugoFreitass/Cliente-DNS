/*
 * Testes da construcao da consulta DNS MX (dns_build_mx_query) e do
 * transaction ID (geracao, leitura e validacao) e da leitura do cabecalho.
 *
 * Compilar e executar a partir da raiz do projeto:
 *   gcc -std=c11 -Wall -Wextra -Wpedantic -Iinclude \
 *       tests/test_dns_packet.c src/dns_packet.c src/dns_name.c -o test_dns_packet
 *   ./test_dns_packet
 */
#include "dns_packet.h"
#include "dns_types.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition, description)                                   \
    do {                                                                \
        if(condition){                                                  \
            printf("[OK]    %s\n", description);                        \
        } else {                                                        \
            printf("[FALHA] %s (%s:%d)\n", description, __FILE__, __LINE__); \
            failures++;                                                 \
        }                                                               \
    } while(0)

static void print_bytes(const char *label, const uint8_t *bytes, size_t length){
    size_t i;

    printf("        %s:", label);
    for(i = 0; i < length; i++){
        printf(" %02X", bytes[i]);
    }
    printf("\n");
}

static void check_packet(const char *description, const uint8_t *actual, size_t actual_length,
                         const uint8_t *expected, size_t expected_length){
    int equal = actual_length == expected_length &&
                memcmp(actual, expected, expected_length) == 0;

    CHECK(equal, description);
    if(!equal){
        print_bytes("esperado", expected, expected_length);
        print_bytes("obtido  ", actual, actual_length);
    }
}

static void test_unb_br(void){
    const uint8_t expected[] = {
        0xAB, 0xCD,                         // ID
        0x01, 0x00,                         // FLAGS
        0x00, 0x01,                         // QDCOUNT
        0x00, 0x00,                         // ANCOUNT
        0x00, 0x00,                         // NSCOUNT
        0x00, 0x00,                         // ARCOUNT
        0x03, 'u', 'n', 'b',                // QNAME
        0x02, 'b', 'r',
        0x00,
        0x00, 0x0F,                         // QTYPE  = MX (15)
        0x00, 0x01                          // QCLASS = IN (1)
    };
    uint8_t packet[DNS_MAX_PACKET_SIZE];
    size_t length = 0;

    CHECK(dns_build_mx_query(packet, sizeof(packet), &length, 0xABCD, "unb.br") == 0,
          "unb.br: consulta montada com sucesso");
    check_packet("unb.br: bytes gerados correspondem ao esperado",
                 packet, length, expected, sizeof(expected));
}

static void test_header_fields(void){
    uint8_t packet[DNS_MAX_PACKET_SIZE];
    size_t length = 0;
    size_t qtype_offset;

    CHECK(dns_build_mx_query(packet, sizeof(packet), &length, 0x1234, "mail.example.com") == 0,
          "mail.example.com: consulta montada com sucesso");

    CHECK(packet[0] == 0x12 && packet[1] == 0x34, "ID gravado em network byte order");
    CHECK(packet[2] == 0x01 && packet[3] == 0x00, "FLAGS exatamente 0x0100");
    CHECK(packet[4] == 0x00 && packet[5] == 0x01, "QDCOUNT exatamente 1");
    CHECK(packet[6] == 0 && packet[7] == 0 && packet[8] == 0 &&
          packet[9] == 0 && packet[10] == 0 && packet[11] == 0,
          "ANCOUNT, NSCOUNT e ARCOUNT iguais a zero");

    // 12 (cabecalho) + 18 (04 mail 07 example 03 com 00) + 4 (QTYPE + QCLASS)
    CHECK(length == 34, "mail.example.com: tamanho total de 34 bytes");

    qtype_offset = length - DNS_QUESTION_FIXED_SIZE;
    CHECK(packet[qtype_offset] == 0x00 && packet[qtype_offset + 1] == DNS_TYPE_MX,
          "QTYPE igual a MX");
    CHECK(packet[qtype_offset + 2] == 0x00 && packet[qtype_offset + 3] == DNS_CLASS_IN,
          "QCLASS igual a IN");
}

static void test_trailing_dot(void){
    uint8_t with_dot[DNS_MAX_PACKET_SIZE];
    uint8_t without_dot[DNS_MAX_PACKET_SIZE];
    size_t with_dot_length = 0;
    size_t without_dot_length = 0;

    CHECK(dns_build_mx_query(with_dot, sizeof(with_dot), &with_dot_length, 1, "example.com.") == 0 &&
          dns_build_mx_query(without_dot, sizeof(without_dot), &without_dot_length, 1, "example.com") == 0,
          "ponto final: ambas as consultas montadas");
    check_packet("ponto final: \"example.com.\" gera os mesmos bytes que \"example.com\"",
                 with_dot, with_dot_length, without_dot, without_dot_length);
}

static void test_buffer_size(void){
    // 12 (cabecalho) + 8 (03 unb 02 br 00) + 4 (QTYPE + QCLASS)
    uint8_t packet[24];
    size_t length = 0;

    CHECK(dns_build_mx_query(packet, 24, &length, 1, "unb.br") == 0 && length == 24,
          "buffer com tamanho exato e aceito");
    CHECK(dns_build_mx_query(packet, 23, &length, 1, "unb.br") == -1,
          "buffer sem espaco para QTYPE/QCLASS e rejeitado");
    CHECK(dns_build_mx_query(packet, 15, &length, 1, "unb.br") == -1,
          "buffer sem espaco para o QNAME e rejeitado");
    CHECK(dns_build_mx_query(packet, 11, &length, 1, "unb.br") == -1,
          "buffer menor que o cabecalho e rejeitado");
}

static void test_invalid_arguments(void){
    uint8_t packet[DNS_MAX_PACKET_SIZE];
    size_t length = 0;
    char long_label[DNS_MAX_LABEL + 5];

    memset(long_label, 'a', DNS_MAX_LABEL + 1);
    strcpy(&long_label[DNS_MAX_LABEL + 1], ".br");

    CHECK(dns_build_mx_query(NULL, sizeof(packet), &length, 1, "unb.br") == -1,
          "packet nulo e rejeitado");
    CHECK(dns_build_mx_query(packet, sizeof(packet), NULL, 1, "unb.br") == -1,
          "packet_length nulo e rejeitado");
    CHECK(dns_build_mx_query(packet, sizeof(packet), &length, 1, NULL) == -1,
          "dominio nulo e rejeitado");
    CHECK(dns_build_mx_query(packet, sizeof(packet), &length, 1, "") == -1,
          "dominio vazio e rejeitado");
    CHECK(dns_build_mx_query(packet, sizeof(packet), &length, 1, "unb..br") == -1,
          "etiqueta vazia e rejeitada");
    CHECK(dns_build_mx_query(packet, sizeof(packet), &length, 1, long_label) == -1,
          "etiqueta maior que 63 bytes e rejeitada");
}

static void test_transaction_id_generation(void){
    uint16_t ids[32];
    int all_equal = 1;
    size_t i;

    CHECK(dns_generate_transaction_id(NULL) == -1, "gerar ID com ponteiro nulo e rejeitado");

    for(i = 0; i < 32; i++){
        if(dns_generate_transaction_id(&ids[i]) != 0){
            all_equal = -1;
            break;
        }
        if(ids[i] != ids[0]){
            all_equal = 0;
        }
    }

    CHECK(all_equal != -1, "IDs gerados com sucesso");
    CHECK(all_equal == 0, "consultas sucessivas nao usam sempre o mesmo ID");
}

static void test_transaction_id_in_query(void){
    uint8_t packet[DNS_MAX_PACKET_SIZE];
    size_t length = 0;
    uint16_t sent_id;
    uint16_t read_id = 0;

    CHECK(dns_generate_transaction_id(&sent_id) == 0 &&
          dns_build_mx_query(packet, sizeof(packet), &length, sent_id, "unb.br") == 0,
          "consulta montada com ID aleatorio");
    CHECK(packet[0] == (uint8_t)(sent_id >> 8) && packet[1] == (uint8_t)(sent_id & 0xFF),
          "ID aleatorio gravado nos dois primeiros bytes em network byte order");
    CHECK(dns_read_transaction_id(packet, length, &read_id) == 0 && read_id == sent_id,
          "ID lido do pacote e igual ao ID enviado");
}

static void test_transaction_id_validation(void){
    const uint8_t response[] = {
        0xBE, 0xEF, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint16_t read_id = 0;

    CHECK(dns_read_transaction_id(response, sizeof(response), &read_id) == 0 && read_id == 0xBEEF,
          "ID da resposta lido em host byte order");
    CHECK(dns_validate_transaction_id(response, sizeof(response), 0xBEEF) == 0,
          "resposta com ID correto e aceita");
    CHECK(dns_validate_transaction_id(response, sizeof(response), 0xBEEE) == -1,
          "resposta com ID diferente e rejeitada");
    CHECK(dns_validate_transaction_id(response, sizeof(response), 0xEFBE) == -1,
          "resposta com ID em byte order invertido e rejeitada");
    CHECK(dns_validate_transaction_id(response, 1, 0xBEEF) == -1,
          "resposta com menos de 2 bytes e rejeitada");
    CHECK(dns_validate_transaction_id(NULL, sizeof(response), 0xBEEF) == -1,
          "resposta nula e rejeitada");
    CHECK(dns_read_transaction_id(response, sizeof(response), NULL) == -1,
          "leitura de ID com destino nulo e rejeitada");
}

static void test_parse_header_valid(void){
    const uint8_t response[] = {
        0xBE, 0xEF,                         // ID
        0x81, 0x80,                         // FLAGS: QR = 1, RD = 1, RA = 1, RCODE = 0
        0x00, 0x01,                         // QDCOUNT
        0x01, 0x02,                         // ANCOUNT
        0x03, 0x04,                         // NSCOUNT
        0x05, 0x06,                         // ARCOUNT
        0x03, 'u', 'n', 'b'                 // inicio da secao Question (ignorado)
    };
    DnsHeader header;

    CHECK(dns_parse_header(response, sizeof(response), &header) == 0,
          "cabecalho valido e interpretado");
    CHECK(header.id == 0xBEEF, "ID convertido para host byte order");
    CHECK(header.flags == 0x8180, "FLAGS convertido para host byte order");
    CHECK(header.questions == 1, "QDCOUNT convertido para host byte order");
    CHECK(header.answers == 0x0102, "ANCOUNT convertido para host byte order");
    CHECK(header.authority == 0x0304, "NSCOUNT convertido para host byte order");
    CHECK(header.additional == 0x0506, "ARCOUNT convertido para host byte order");
    CHECK(dns_header_is_response(&header) == 1, "QR = 1 identificado como resposta");
    CHECK(dns_header_is_truncated(&header) == 0, "TC = 0 identificado como nao truncada");
    CHECK(dns_header_rcode(&header) == DNS_RCODE_NOERROR, "RCODE = 0 (NOERROR) extraido");
}

static void test_parse_header_flags(void){
    uint8_t response[DNS_HEADER_SIZE] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DnsHeader header;

    CHECK(dns_parse_header(response, sizeof(response), &header) == 0 &&
          dns_header_rcode(&header) == DNS_RCODE_NXDOMAIN,
          "RCODE = 3 (NXDOMAIN) extraido");

    response[3] = 0x82;
    CHECK(dns_parse_header(response, sizeof(response), &header) == 0 &&
          dns_header_rcode(&header) == DNS_RCODE_SERVFAIL,
          "RCODE = 2 (SERVFAIL) extraido");

    response[2] = 0x83;
    response[3] = 0x80;
    CHECK(dns_parse_header(response, sizeof(response), &header) == 0 &&
          dns_header_is_truncated(&header) == 1,
          "TC = 1 identificado como truncada");
}

static void test_parse_header_invalid(void){
    const uint8_t query[DNS_HEADER_SIZE] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const uint8_t response[DNS_HEADER_SIZE] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DnsHeader header;

    header.id = 0xAAAA;
    CHECK(dns_parse_header(query, sizeof(query), &header) == -1,
          "mensagem com QR = 0 e rejeitada");
    CHECK(header.id == 0xAAAA, "cabecalho de saida nao e alterado quando ha erro");
    CHECK(dns_parse_header(response, DNS_HEADER_SIZE - 1, &header) == -1,
          "pacote menor que 12 bytes e rejeitado");
    CHECK(dns_parse_header(response, 0, &header) == -1,
          "pacote vazio e rejeitado");
    CHECK(dns_parse_header(NULL, sizeof(response), &header) == -1,
          "pacote nulo e rejeitado");
    CHECK(dns_parse_header(response, sizeof(response), NULL) == -1,
          "cabecalho de saida nulo e rejeitado");
}

int main(void){
    test_unb_br();
    test_header_fields();
    test_trailing_dot();
    test_buffer_size();
    test_invalid_arguments();
    test_transaction_id_generation();
    test_transaction_id_in_query();
    test_transaction_id_validation();
    test_parse_header_valid();
    test_parse_header_flags();
    test_parse_header_invalid();

    if(failures > 0){
        printf("\n%d teste(s) falharam\n", failures);
        return 1;
    }

    printf("\nTodos os testes passaram\n");
    return 0;
}

/*
 * Testes unitarios para codificacao, decodificacao e compressao de nomes DNS.
 *
 * Compilar e executar a partir da raiz do projeto:
 *   gcc -std=c11 -Wall -Wextra -Wpedantic -Iinclude \
 *       tests/test_dns_name.c src/dns_name.c -o test_dns_name
 *   ./test_dns_name
 */
#include "dns_name.h"
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

static void check_bytes(const char *description, const uint8_t *actual, size_t actual_length,
                        const uint8_t *expected, size_t expected_length){
    int equal = actual_length == expected_length &&
                memcmp(actual, expected, expected_length) == 0;

    CHECK(equal, description);
    if(!equal){
        print_bytes("esperado", expected, expected_length);
        print_bytes("obtido  ", actual, actual_length);
    }
}

/* -------------------------------------------------------------------------
 * Testes de Codificacao (dns_encode_name)
 * ------------------------------------------------------------------------- */

static void test_encode_valid(void){
    uint8_t buffer[DNS_MAX_NAME];
    size_t offset = 0;

    // example.com -> 07 example 03 com 00
    const uint8_t expected_example[] = {
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00
    };
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "example.com") == 0 &&
          offset == sizeof(expected_example),
          "codificar example.com com sucesso e offset correto");
    check_bytes("bytes gerados para example.com", buffer, offset,
                expected_example, sizeof(expected_example));

    // mail.example.com -> 04 mail 07 example 03 com 00
    const uint8_t expected_mail[] = {
        0x04, 'm', 'a', 'i', 'l',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00
    };
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "mail.example.com") == 0 &&
          offset == sizeof(expected_mail),
          "codificar mail.example.com com sucesso");
    check_bytes("bytes gerados para mail.example.com", buffer, offset,
                expected_mail, sizeof(expected_mail));

    // localhost -> 09 localhost 00
    const uint8_t expected_localhost[] = {
        0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
        0x00
    };
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "localhost") == 0 &&
          offset == sizeof(expected_localhost),
          "codificar localhost com sucesso");
    check_bytes("bytes gerados para localhost", buffer, offset,
                expected_localhost, sizeof(expected_localhost));

    // Ponto final opcional: "example.com." equivale a "example.com"
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "example.com.") == 0 &&
          offset == sizeof(expected_example),
          "ponto final opcional: \"example.com.\" codificado com sucesso");
    check_bytes("bytes de example.com. correspondem a example.com", buffer, offset,
                expected_example, sizeof(expected_example));

    // Offset inicial diferente de zero
    buffer[0] = 0xAA;
    buffer[1] = 0xBB;
    offset = 2;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "localhost") == 0 &&
          offset == 2 + sizeof(expected_localhost),
          "codificacao preserva bytes anteriores e atualiza offset relativo");
    check_bytes("bytes de localhost a partir do offset 2", &buffer[2], sizeof(expected_localhost),
                expected_localhost, sizeof(expected_localhost));
}

static void test_encode_invalid(void){
    uint8_t buffer[DNS_MAX_NAME];
    size_t offset = 0;
    char long_label[DNS_MAX_LABEL + 10];

    // Nome vazio
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "") == -1 && offset == 0,
          "nome vazio e rejeitado");

    // Ponto isolado (nome vazio com ponto)
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, ".") == -1 && offset == 0,
          "ponto isolado e rejeitado");

    // Etiqueta vazia no meio
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, "example..com") == -1 && offset == 0,
          "etiqueta vazia no meio (..) e rejeitada");

    // Ponto inicial
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, ".example.com") == -1 && offset == 0,
          "ponto inicial e rejeitado");

    // Etiqueta maior que 63 bytes (DNS_MAX_LABEL)
    memset(long_label, 'a', DNS_MAX_LABEL + 1);
    strcpy(&long_label[DNS_MAX_LABEL + 1], ".com");
    offset = 0;
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, long_label) == -1 && offset == 0,
          "etiqueta maior que 63 bytes e rejeitada");

    // Buffer insuficiente
    offset = 0;
    CHECK(dns_encode_name(buffer, 5, &offset, "example.com") == -1 && offset == 0,
          "buffer menor que o nome codificado e rejeitado");

    // Offset inicial alem do buffer_size
    offset = 10;
    CHECK(dns_encode_name(buffer, 5, &offset, "example.com") == -1 && offset == 10,
          "offset inicial maior que o buffer e rejeitado");

    // Parametros nulos
    offset = 0;
    CHECK(dns_encode_name(NULL, sizeof(buffer), &offset, "example.com") == -1,
          "buffer nulo e rejeitado");
    CHECK(dns_encode_name(buffer, sizeof(buffer), NULL, "example.com") == -1,
          "offset nulo e rejeitado");
    CHECK(dns_encode_name(buffer, sizeof(buffer), &offset, NULL) == -1 && offset == 0,
          "nome nulo e rejeitado");
}

/* -------------------------------------------------------------------------
 * Testes de Decodificacao (dns_decode_name) e Compressao
 * ------------------------------------------------------------------------- */

/*
 * Pacote usado nos testes de compressao:
 *   offset  0: 07 example 03 com 00   -> "example.com"
 *   offset 13: 03 www C0 00           -> "www" + ponteiro para offset 0
 *   offset 19: C0 0D                  -> ponteiro para offset 13
 */
static const uint8_t compressed_packet[] = {
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x03, 'w', 'w', 'w', 0xC0, 0x00,
    0xC0, 0x0D
};

static int decode(const uint8_t *packet, size_t packet_size, size_t start,
                  const char *expected_name, size_t expected_offset){
    char output[DNS_MAX_NAME + 1];
    size_t offset = start;

    if(dns_decode_name(packet, packet_size, &offset, output, sizeof(output)) != 0){
        printf("        retorno de erro inesperado\n");
        return 0;
    }

    if(strcmp(output, expected_name) != 0 || offset != expected_offset){
        printf("        esperado \"%s\" (offset %zu), obtido \"%s\" (offset %zu)\n",
               expected_name, expected_offset, output, offset);
        return 0;
    }

    return 1;
}

static int rejects(const uint8_t *packet, size_t packet_size, size_t start){
    char output[DNS_MAX_NAME + 1];
    size_t offset = start;

    return dns_decode_name(packet, packet_size, &offset, output, sizeof(output)) == -1 &&
           offset == start;
}

static void test_decode_uncompressed(void){
    const uint8_t www_example_com[] = {
        0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00
    };
    const uint8_t with_prefix[] = { 0xFF, 0xFF, 0x03, 'u', 'n', 'b', 0x02, 'b', 'r', 0x00, 0x00, 0x0F };
    const uint8_t root[] = { 0x00 };

    CHECK(decode(www_example_com, sizeof(www_example_com), 0, "www.example.com", 17),
          "nome sem compressao com multiplas etiquetas");
    CHECK(decode(with_prefix, sizeof(with_prefix), 2, "unb.br", 10),
          "nome no meio do pacote: offset final aponta para o byte seguinte");
    CHECK(decode(root, sizeof(root), 0, "", 1),
          "nome raiz (byte 0 isolado) gera texto vazio");
}

static void test_decode_compressed(void){
    CHECK(decode(compressed_packet, sizeof(compressed_packet), 13, "www.example.com", 19),
          "nome com ponteiro: offset final fica logo depois do ponteiro");
    CHECK(decode(compressed_packet, sizeof(compressed_packet), 19, "www.example.com", 21),
          "ponteiro para outro ponteiro");
}

static void test_decode_invalid(void){
    const uint8_t truncated_label[] = { 0x03, 'w', 'w' };
    const uint8_t missing_terminator[] = { 0x03, 'w', 'w', 'w' };
    const uint8_t truncated_pointer[] = { 0x03, 'w', 'w', 'w', 0xC0 };
    const uint8_t pointer_outside[] = { 0xC0, 0x50 };
    const uint8_t self_pointer[] = { 0xC0, 0x00 };
    const uint8_t circular_pointers[] = { 0xC0, 0x02, 0xC0, 0x00 };
    const uint8_t reserved_prefix[] = { 0x40, 'a', 0x00 };
    const uint8_t dot_in_label[] = { 0x03, 'a', '.', 'b', 0x00 };
    char output[DNS_MAX_NAME + 1];
    size_t offset = 0;

    CHECK(rejects(truncated_label, sizeof(truncated_label), 0), "etiqueta truncada e rejeitada");
    CHECK(rejects(missing_terminator, sizeof(missing_terminator), 0), "nome sem byte 0 final e rejeitado");
    CHECK(rejects(truncated_pointer, sizeof(truncated_pointer), 0), "ponteiro truncado e rejeitado");
    CHECK(rejects(pointer_outside, sizeof(pointer_outside), 0), "ponteiro fora do pacote e rejeitado");
    CHECK(rejects(self_pointer, sizeof(self_pointer), 0), "ponteiro para si mesmo e rejeitado");
    CHECK(rejects(circular_pointers, sizeof(circular_pointers), 0), "ponteiros circulares sao rejeitados");
    CHECK(rejects(reserved_prefix, sizeof(reserved_prefix), 0), "prefixo reservado 01 e rejeitado");
    CHECK(rejects(dot_in_label, sizeof(dot_in_label), 0), "etiqueta contendo '.' e rejeitada");
    CHECK(rejects(compressed_packet, sizeof(compressed_packet), sizeof(compressed_packet)),
          "offset inicial no fim do pacote e rejeitado");

    CHECK(dns_decode_name(NULL, 1, &offset, output, sizeof(output)) == -1, "pacote nulo e rejeitado");
    CHECK(dns_decode_name(compressed_packet, sizeof(compressed_packet), NULL, output, sizeof(output)) == -1,
          "offset nulo e rejeitado");
    CHECK(dns_decode_name(compressed_packet, sizeof(compressed_packet), &offset, NULL, sizeof(output)) == -1,
          "saida nula e rejeitada");
}

static void test_decode_output_size(void){
    char output[16];
    size_t offset = 13;

    // "www.example.com" tem 15 caracteres + '\0'
    CHECK(dns_decode_name(compressed_packet, sizeof(compressed_packet), &offset, output, 15) == -1 &&
          offset == 13,
          "buffer de saida insuficiente e rejeitado");
    CHECK(dns_decode_name(compressed_packet, sizeof(compressed_packet), &offset, output, 16) == 0 &&
          strcmp(output, "www.example.com") == 0,
          "buffer de saida com tamanho exato e aceito");
}

int main(void){
    printf("=== Testes de Codificacao de Nomes DNS ===\n");
    test_encode_valid();
    test_encode_invalid();

    printf("\n=== Testes de Decodificacao e Compressao de Nomes DNS ===\n");
    test_decode_uncompressed();
    test_decode_compressed();
    test_decode_invalid();
    test_decode_output_size();

    if(failures > 0){
        printf("\n%d teste(s) falharam\n", failures);
        return 1;
    }

    printf("\nTodos os testes de nomes DNS passaram com sucesso!\n");
    return 0;
}

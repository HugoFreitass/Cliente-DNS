/*
 * Testes da decodificacao de nomes DNS (dns_decode_name), com e sem compressao.
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
    test_decode_uncompressed();
    test_decode_compressed();
    test_decode_invalid();
    test_decode_output_size();

    if(failures > 0){
        printf("\n%d teste(s) falharam\n", failures);
        return 1;
    }

    printf("\nTodos os testes passaram\n");
    return 0;
}

#include "dns_packet.h"

#include "dns_name.h"
#include "dns_types.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Escreve um inteiro de 16 bits em network byte order (big-endian)
static void dns_write_u16(uint8_t *destination, uint16_t value){
    uint16_t network_value = htons(value); // Host to Network Short

    memcpy(destination, &network_value, sizeof(network_value));
}

// Le um inteiro de 16 bits em network byte order e o converte para host byte order
static uint16_t dns_read_u16(const uint8_t *source){
    uint16_t network_value;

    memcpy(&network_value, source, sizeof(network_value));

    return ntohs(network_value); // Network to Host Short
}

int dns_build_mx_query(uint8_t *packet, size_t packet_size, size_t *packet_length,
                       uint16_t transaction_id, const char *domain){
    size_t offset;

    if(!packet || !packet_length || !domain){
        return -1;
    }

    if(packet_size < DNS_HEADER_SIZE){
        return -1;
    }

    // Cabecalho (RFC 1035, secao 4.1.1)
    dns_write_u16(&packet[0], transaction_id);           // ID
    dns_write_u16(&packet[2], DNS_FLAGS_STANDARD_QUERY); // FLAGS: consulta padrao, RD = 1
    dns_write_u16(&packet[4], 1);                        // QDCOUNT
    dns_write_u16(&packet[6], 0);                        // ANCOUNT
    dns_write_u16(&packet[8], 0);                        // NSCOUNT
    dns_write_u16(&packet[10], 0);                       // ARCOUNT

    // Pergunta (RFC 1035, secao 4.1.2): QNAME, QTYPE, QCLASS
    offset = DNS_HEADER_SIZE;
    if(dns_encode_name(packet, packet_size, &offset, domain) != 0){
        return -1;
    }

    if(packet_size - offset < DNS_QUESTION_FIXED_SIZE){
        return -1;
    }

    dns_write_u16(&packet[offset], DNS_TYPE_MX);      // QTYPE
    dns_write_u16(&packet[offset + 2], DNS_CLASS_IN); // QCLASS
    offset += DNS_QUESTION_FIXED_SIZE;

    *packet_length = offset;

    return 0;
}

// Alternativa a /dev/urandom: rand() semeado uma unica vez por execucao
static uint16_t dns_fallback_random_u16(void){
    static int seeded = 0;

    if(!seeded){
        srand((unsigned int)time(NULL) ^ (unsigned int)clock());
        seeded = 1;
    }

    // RAND_MAX pode ter apenas 15 bits; combina duas chamadas para os 16 bits
    return (uint16_t)(((unsigned int)rand() << 8) ^ (unsigned int)rand());
}

int dns_generate_transaction_id(uint16_t *transaction_id){
    FILE *urandom;
    uint8_t bytes[2];
    size_t bytes_read = 0;

    if(!transaction_id){
        return -1;
    }

    urandom = fopen("/dev/urandom", "rb");
    if(urandom){
        bytes_read = fread(bytes, 1, sizeof(bytes), urandom);
        fclose(urandom);
    }

    if(bytes_read == sizeof(bytes)){
        *transaction_id = (uint16_t)((bytes[0] << 8) | bytes[1]);
    } else {
        *transaction_id = dns_fallback_random_u16();
    }

    return 0;
}

int dns_read_transaction_id(const uint8_t *packet, size_t packet_size, uint16_t *transaction_id){
    if(!packet || !transaction_id || packet_size < sizeof(uint16_t)){
        return -1;
    }

    *transaction_id = dns_read_u16(packet);

    return 0;
}

int dns_validate_transaction_id(const uint8_t *response, size_t response_length, uint16_t expected_id){
    uint16_t received_id;

    if(dns_read_transaction_id(response, response_length, &received_id) != 0){
        return -1;
    }

    if(received_id != expected_id){
        return -1;
    }

    return 0;
}

int dns_parse_header(const uint8_t *packet, size_t packet_size, DnsHeader *header){
    DnsHeader parsed;

    if(!packet || !header || packet_size < DNS_HEADER_SIZE){
        return -1;
    }

    // Cabecalho (RFC 1035, secao 4.1.1)
    parsed.id = dns_read_u16(&packet[0]);
    parsed.flags = dns_read_u16(&packet[2]);
    parsed.questions = dns_read_u16(&packet[4]);
    parsed.answers = dns_read_u16(&packet[6]);
    parsed.authority = dns_read_u16(&packet[8]);
    parsed.additional = dns_read_u16(&packet[10]);

    // QR = 0 indica uma consulta, nao uma resposta
    if(!dns_header_is_response(&parsed)){
        return -1;
    }

    *header = parsed;

    return 0;
}

int dns_header_is_response(const DnsHeader *header){
    return header && (header->flags & DNS_FLAG_QR) != 0;
}

int dns_header_is_truncated(const DnsHeader *header){
    return header && (header->flags & DNS_FLAG_TC) != 0;
}

uint8_t dns_header_rcode(const DnsHeader *header){
    if(!header){
        return 0;
    }

    return (uint8_t)(header->flags & DNS_RCODE_MASK);
}

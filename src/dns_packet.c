#include "dns_packet.h"

#include "dns_name.h"
#include "dns_types.h"

#include <arpa/inet.h>
#include <string.h>

// Escreve um inteiro de 16 bits em network byte order (big-endian)
static void dns_write_u16(uint8_t *destination, uint16_t value){
    uint16_t network_value = htons(value); // Host to Network Short

    memcpy(destination, &network_value, sizeof(network_value));
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

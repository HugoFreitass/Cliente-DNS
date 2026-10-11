#include "dns_name.h"

#include "dns_types.h"

#include <string.h>

int dns_encode_name(uint8_t *buffer, size_t buffer_size, size_t *offset, const char *name){
    size_t name_length;
    size_t encoded_length;
    size_t label_start;
    size_t position;
    size_t i;

    if(!buffer || !offset || !name){
        return -1;
    }

    name_length = strlen(name);

    // Ponto final opcional: "example.com." equivale a "example.com"
    if(name_length > 0 && name[name_length - 1] == '.'){
        name_length--;
    }

    if(name_length == 0){
        return -1;
    }

    // Cada '.' vira um byte de tamanho, mais o tamanho da primeira etiqueta e o 0 final
    encoded_length = name_length + 2;
    if(encoded_length > DNS_MAX_NAME){
        return -1;
    }

    if(*offset > buffer_size || buffer_size - *offset < encoded_length){
        return -1;
    }

    position = *offset;
    label_start = 0;

    for(i = 0; i <= name_length; i++){
        if(i == name_length || name[i] == '.'){
            size_t label_length = i - label_start;

            if(label_length == 0 || label_length > DNS_MAX_LABEL){
                return -1;
            }

            buffer[position++] = (uint8_t)label_length;
            memcpy(&buffer[position], &name[label_start], label_length);
            position += label_length;
            label_start = i + 1;
        }
    }

    buffer[position++] = 0;
    *offset = position;

    return 0;
}

int dns_decode_name(const uint8_t *packet, size_t packet_size, size_t *offset,
                    char *output, size_t output_size){
    size_t position;
    size_t output_length = 0;
    size_t encoded_length = 0;

    if(!packet || !offset || !output || output_size == 0){
        return -1;
    }

    position = *offset;

    for(;;){
        uint8_t label_length;

        if(position >= packet_size){
            return -1;
        }

        label_length = packet[position];

        // Sem suporte a ponteiro nesta etapa: qualquer prefixo diferente de 00 e rejeitado
        if((label_length & 0xC0) != 0){
            return -1;
        }

        if(label_length == 0){
            position++;
            break;
        }

        if(label_length > DNS_MAX_LABEL){
            return -1;
        }

        if(packet_size - position - 1 < label_length){
            return -1;
        }

        encoded_length += (size_t)label_length + 1;
        if(encoded_length + 1 > DNS_MAX_NAME){
            return -1;
        }

        // Etiquetas com '.' ou '\0' nao podem ser representadas no formato textual
        if(memchr(&packet[position + 1], '.', label_length) ||
           memchr(&packet[position + 1], '\0', label_length)){
            return -1;
        }

        // Espaco para o '.' separador, a etiqueta e o '\0' final
        if(output_length + (output_length > 0) + label_length + 1 > output_size){
            return -1;
        }

        if(output_length > 0){
            output[output_length++] = '.';
        }

        memcpy(&output[output_length], &packet[position + 1], label_length);
        output_length += label_length;
        position += (size_t)label_length + 1;
    }

    output[output_length] = '\0';
    *offset = position;

    return 0;
}

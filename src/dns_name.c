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

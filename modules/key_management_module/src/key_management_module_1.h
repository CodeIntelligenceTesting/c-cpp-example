#ifndef KEY_MANAGEMENT_MODULE_1_H
#define KEY_MANAGEMENT_MODULE_1_H

#include <stdint.h>

#include "key_management_module_types.h"

extern uint8_t HSM_get_random_byte();

void key_management_create_key(uint8_t * key, uint8_t length);
void key_management_create_nonce(uint8_t * nonce, uint8_t length);

#endif
#include "key_management_1.h"

uint8_t *generate_random_bytes(uint8_t *buffer, uint8_t length) {
  for (int i = 0; i < length; i++) {
    buffer[i] = HSM_get_random_byte();
  }
  return buffer;
}

void key_management_create_key(uint8_t *key, uint8_t length) {
  generate_random_bytes(key, length);
}

void key_management_create_nonce(uint8_t *nonce, uint8_t length) {
  generate_random_bytes(nonce, length);
}

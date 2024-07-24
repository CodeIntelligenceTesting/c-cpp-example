#ifndef CRYPTO_MODULE_TYPES_H
#define CRYPTO_MODULE_TYPES_H

#include <stdint.h>

#define NONCE_LENGTH 64
#define KEY_LENGTH 64
#define HMAC_LENGTH 64

enum crypto_state {
  uninitialized,
  initialized,
  key_set,
  nonce_set,
  nonce_and_key_set
};

typedef struct crypto_nonce {
  uint8_t nonce[NONCE_LENGTH];
  int time_of_creation;
} crypto_nonce;

typedef struct crypto_key {
  uint8_t key[KEY_LENGTH];
} crypto_key;

typedef struct crypto_hmac {
  uint8_t hmac[HMAC_LENGTH];
} crypto_hmac;

typedef struct crypto_message {
  uint8_t key[HMAC_LENGTH];
} crypto_message;

enum crypto_return_status {
  valid_key_provided,
  invalid_key_provided,
  valid_nonce_provided,
  invalid_nonce_provided,
  wrong_state,
  hmac_successfully_calculated,
  error_during_hmac_calculation,
  invalid_hmac,
  valid_hmac
};

#endif
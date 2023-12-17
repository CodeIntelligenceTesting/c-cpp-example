#ifndef CRYPTO_MODULE_2_H
#define CRYPTO MODULE_2_H

#include "crypto_1.h"
#include "crypto_types.h"

enum crypto_return_status crypto_verify_nonce(crypto_nonce *nonce);
enum crypto_return_status crypto_verify_key(crypto_key key);

#endif
#ifndef CRYPTO_MODULE_2_H
#define CRYPTO MODULE_2_H

#include "crypto_module_types.h"
#include "crypto_module_1.h"

enum crypto_return_status crypto_verify_nonce(crypto_nonce * nonce);
enum crypto_return_status crypto_verify_key(crypto_key key);

#endif
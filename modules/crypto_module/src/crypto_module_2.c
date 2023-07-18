#include "crypto_module_types.h"
#include "crypto_module_2.h"

#include "time_module_1.h"

#include <limits.h>


enum crypto_return_status crypto_verify_nonce(crypto_nonce * nonce) {
    for (int i = 0; i < NONCE_LENGTH; i++ ) {
        if (nonce->nonce[i] != 0) {
            int ct = current_time();
            if (ct > INT_MIN + 300 && nonce->time_of_creation > ct - 300) {
                return valid_nonce_provided;
            }
        }
    }
    //Nonce is only zero
    return invalid_nonce_provided;
}


enum crypto_return_status crypto_verify_key(crypto_key key) {
    for (int i = 0; i < KEY_LENGTH; i++ ) {
        if (key.key[i] != 0) {
            return valid_key_provided;
        }
    }
    //Key is only zero
    return invalid_key_provided;
}

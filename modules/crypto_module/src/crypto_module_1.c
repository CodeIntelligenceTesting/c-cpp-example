#include <string.h>
#include <stdlib.h>

#include "crypto_module_1.h"
#include "crypto_module_2.h"


static enum crypto_state current_state = uninitialized;
static crypto_key current_key = {0};
static crypto_nonce * current_nonce = 0;

void crypto_init() {
    memset(&current_key, 0 , sizeof(current_key));
    if (current_nonce != 0) {
        free(current_nonce);
    }
    current_nonce = calloc(1, sizeof(crypto_nonce));
    current_state = initialized;
}

enum crypto_state crypto_get_state() {
    return current_state;
}

enum crypto_return_status crypto_set_key(crypto_key key) {
    if (crypto_verify_key(key) == valid_key_provided) {
        current_key = key;
        if (current_state == nonce_set) {
            current_state = nonce_and_key_set;
        }
        else {
            current_state = key_set;
        }
        return valid_key_provided;
    }
    return invalid_key_provided;
}

enum crypto_return_status crypto_set_nonce(crypto_nonce nonce) {
    if(crypto_verify_nonce(&nonce) == valid_nonce_provided) {
        if (current_nonce == 0) {
            crypto_init();
        }
        for (int i = 0; i < NONCE_LENGTH; i++) {
            current_nonce->nonce[i] = nonce.nonce[i];
        }
        current_nonce->time_of_creation = nonce.time_of_creation;
        if (current_state == key_set) {
            current_state = nonce_and_key_set;
        }
        else {
            current_state = nonce_set;
        }
        return valid_nonce_provided;
    }
    return invalid_nonce_provided;
}

enum crypto_return_status crypto_calculate_hmac(const uint8_t * message, int len, crypto_hmac * hmac) {
    if (current_state == nonce_and_key_set) {
        if (current_nonce != 0) {
            if (third_party_library_calc_hmac(message, len, &(current_key.key), current_nonce->nonce, hmac->hmac) == 0) {
                //Delete nonce to make sure it is only used once
                free(current_nonce);
                current_nonce = NULL;
                return hmac_successfully_calculated;
            }
        }
        return error_during_hmac_calculation;
    }
    return wrong_state;
}

enum crypto_return_status crypto_verify_hmac(const uint8_t * message, int len, crypto_hmac * hmac) {
    crypto_hmac own_hmac;
    enum crypto_return_status hmac_calc_status = crypto_calculate_hmac(message, len, &own_hmac);
    if (hmac_calc_status != hmac_successfully_calculated) {
        return hmac_calc_status;
    }
    for (int i = 0; i < HMAC_LENGTH; i++) {
        if (own_hmac.hmac[i] != hmac->hmac[i]) {
            return invalid_hmac;
        } 
    }
    return valid_hmac;
}
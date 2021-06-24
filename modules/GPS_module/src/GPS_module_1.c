#include <string.h>

#include "GPS_module_types.h"
#include "GPS_module_1.h"

#include "crypto_module_types.h"
#include "crypto_module_1.h"

GPS_position current_destination;


enum GPS_return_status init_crypto_module() {
    crypto_init();
    crypto_key key = {0};
    key_management_create_key(&key, sizeof(key));
    if (crypto_set_key(key) == valid_key_provided) {
        crypto_nonce nonce = {0};
        key_management_create_nonce(&nonce, sizeof(nonce));
        if (crypto_set_nonce(nonce) == valid_nonce_provided) {
            return GPS_success;
        }
    }
    return GPS_failure;
}

enum GPS_return_status set_destination_postition(GPS_position position) {
    current_destination = position;
    return GPS_success;
}

GPS_position get_destination_position() {
    return current_destination;
}

enum GPS_return_status get_current_position(GPS_position * position) {
    uint8_t position_as_bytes[12];
    uint8_t hmac_as_bytes[HMAC_LENGTH];
    if (GPS_driver_obtain_current_position(position_as_bytes, hmac_as_bytes) == 0) {
        if (crypto_verify_hmac(position_as_bytes, 16, hmac_as_bytes) == valid_hmac) {
            GPS_position pos = {
                position_as_bytes[0] << 1 + position_as_bytes[1],
                position_as_bytes[2] << 1 + position_as_bytes[3],
                position_as_bytes[4] << 1 + position_as_bytes[5],
                position_as_bytes[6] << 1 + position_as_bytes[7],
                position_as_bytes[8] << 1 + position_as_bytes[9],
                position_as_bytes[10] << 1 + position_as_bytes[11]
            };
            *position = pos;
            return GPS_success;
        }
    }
    return GPS_failure;
}

#include <stdint.h>
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif
        
#include "crypto_module_2.h"
#include "key_management_module_1.h"
#include "crypto_module_1.h"
#include "time_module_1.h"
#include "GPS_module_1.h"

#ifdef __cplusplus
}
#endif

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {

    FuzzedDataProvider fdp(data, size);
    
    // Ensure a minimum data length
    int message_length = fdp.ConsumeIntegral<uint8_t>();
    if (size < HMAC_LENGTH + message_length) return;

    std::vector<uint8_t> message = fdp.ConsumeBytes<uint8_t>(message_length);
    std::vector<uint8_t> hmac_key = fdp.ConsumeBytesWithTerminator<uint8_t>(HMAC_LENGTH);

    crypto_hmac hmac = {0};
    std::memcpy(hmac.hmac, hmac_key.data(), HMAC_LENGTH);
    
    crypto_calculate_hmac(message.data(), message.size(), &hmac);
}
        
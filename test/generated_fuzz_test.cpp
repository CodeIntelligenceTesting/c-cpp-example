
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


void mocklib_set_data(void *fuzzed_data_provider);
void ConsumeDataAndFillRestWithZeros(void *destination, size_t num_bytes);

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {
    
    // Ensure a minimum data length
    if (size < 100) return;

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);
    mocklib_set_data(&fdp);

    int number_of_functions = fdp.ConsumeIntegralInRange<int>(1, 100);
    for (int i = 0; i < number_of_functions; i++) {
        int function_id = fdp.ConsumeIntegralInRange<int>(0, 15);
        switch(function_id) {
        
            case 0:
            {
                std::vector<uint8_t> nonce = fdp.ConsumeBytes<uint8_t>(sizeof(uint8_t) * fdp.ConsumeIntegral<uint8_t>());
                
                // The parameter "length" seems to represent the length of a buffer/array. In this case, we usually
                // don't want to provide fuzzer-generated lengths that differ from the actual length of the buffer.
                // If you confirm that the parameter is a length parameter, you can get the length of 
                // the fuzzer-generated buffer as follows (replace "buffer" with the actual variable):
                //     uint8_t length = buffer.size();
                uint8_t length = nonce.size();
                
                key_management_create_nonce(nonce.data(), length);
                break;
            }
        
            case 1:
            {
                crypto_key key = {0};
                ConsumeDataAndFillRestWithZeros(key.key, 64);
                
                crypto_verify_key(key);
                break;
            }
        
            case 2:
            {
                GPS_position position = {0};
                position.longitude_degree = fdp.ConsumeIntegral<uint8_t>();
                position.longitude_minute = fdp.ConsumeIntegral<uint8_t>();
                position.longitude_second = fdp.ConsumeIntegral<uint8_t>();
                position.latitude_degree = fdp.ConsumeIntegral<uint8_t>();
                position.latitude_minute = fdp.ConsumeIntegral<uint8_t>();
                position.latitude_second = fdp.ConsumeIntegral<uint8_t>();
                
                set_destination_postition(position);
                break;
            }
        
            case 3:
            {
                std::vector<uint8_t> message = fdp.ConsumeBytes<uint8_t>(sizeof(uint8_t) * fdp.ConsumeIntegral<uint8_t>());
                
                // The parameter "len" seems to represent the length of a buffer/array. In this case, we usually
                // don't want to provide fuzzer-generated lengths that differ from the actual length of the buffer.
                // If you confirm that the parameter is a length parameter, you can get the length of 
                // the fuzzer-generated buffer as follows (replace "buffer" with the actual variable):
                //     int len = buffer.size();
                int len = message.size();
                crypto_hmac hmac = {0};
                ConsumeDataAndFillRestWithZeros(hmac.hmac, 64);
                
                crypto_calculate_hmac(message.data(), len, &hmac);
                break;
            }
        
            case 4:
            {
                crypto_nonce nonce = {0};
                ConsumeDataAndFillRestWithZeros(nonce.nonce, 64);
                nonce.time_of_creation = fdp.ConsumeIntegral<int>();
                
                crypto_verify_nonce(&nonce);
                break;
            }
        
            case 5:
            {
                init_crypto_module();
                break;
            }
        
            case 6:
            {
                std::vector<uint8_t> key = fdp.ConsumeBytes<uint8_t>(sizeof(uint8_t) * fdp.ConsumeIntegral<uint8_t>());
                
                // The parameter "length" seems to represent the length of a buffer/array. In this case, we usually
                // don't want to provide fuzzer-generated lengths that differ from the actual length of the buffer.
                // If you confirm that the parameter is a length parameter, you can get the length of 
                // the fuzzer-generated buffer as follows (replace "buffer" with the actual variable):
                //     uint8_t length = buffer.size();
                uint8_t length = key.size();
                
                key_management_create_key(key.data(), length);
                break;
            }
        
            case 7:
            {
                crypto_get_state();
                break;
            }
        
            case 8:
            {
                current_time();
                break;
            }
        
            case 9:
            {
                GPS_position position = {0};
                position.longitude_degree = fdp.ConsumeIntegral<uint8_t>();
                position.longitude_minute = fdp.ConsumeIntegral<uint8_t>();
                position.longitude_second = fdp.ConsumeIntegral<uint8_t>();
                position.latitude_degree = fdp.ConsumeIntegral<uint8_t>();
                position.latitude_minute = fdp.ConsumeIntegral<uint8_t>();
                position.latitude_second = fdp.ConsumeIntegral<uint8_t>();
                
                get_current_position(&position);
                break;
            }
        
            case 10:
            {
                crypto_nonce nonce = {0};
                ConsumeDataAndFillRestWithZeros(nonce.nonce, 64);
                nonce.time_of_creation = fdp.ConsumeIntegral<int>();
                
                crypto_set_nonce(nonce);
                break;
            }
        
            case 11:
            {
                crypto_init();
                break;
            }
        
            case 12:
            {
                get_destination_position();
                break;
            }
        
            case 13:
            {
                std::vector<uint8_t> message = fdp.ConsumeBytes<uint8_t>(sizeof(uint8_t) * fdp.ConsumeIntegral<uint8_t>());
                
                // The parameter "len" seems to represent the length of a buffer/array. In this case, we usually
                // don't want to provide fuzzer-generated lengths that differ from the actual length of the buffer.
                // If you confirm that the parameter is a length parameter, you can get the length of 
                // the fuzzer-generated buffer as follows (replace "buffer" with the actual variable):
                //     int len = buffer.size();
                int len = message.size();
                crypto_hmac hmac = {0};
                ConsumeDataAndFillRestWithZeros(hmac.hmac, 64);
                
                crypto_verify_hmac(message.data(), len, &hmac);
                break;
            }
        
            case 14:
            {
                crypto_key key = {0};
                ConsumeDataAndFillRestWithZeros(key.key, 64);
                
                crypto_set_key(key);
                break;
            }
        
        }
    }
}
        

#include <vector>
#include <cstdint>
#include <iostream>
#include <iomanip>
        
#include <fuzzer/FuzzedDataProvider.h>
        
        
        
        
        
static FuzzedDataProvider *fdp;

// This function received the fuzzer generated data from the fuzz target.
// It needs to be called at the beginning of the LLVMFuzzerTestOneInput function.
void mocklib_set_data(void *fuzzed_data_provider) {
    fdp = (FuzzedDataProvider *) fuzzed_data_provider;
}
        
// Wrapper function for FuzzedDataProvider.h
// Writes |num_bytes| of input data to the given destination pointer. If there
// is not enough data left, writes all remaining bytes and fills the rest with zeros.
// Return value is the number of bytes written.
void ConsumeDataAndFillRestWithZeros(void *destination, size_t num_bytes) {
    if (destination != nullptr) {
        size_t num_consumed_bytes = fdp->ConsumeData(destination, num_bytes);
        if (num_bytes > num_consumed_bytes) {
            size_t num_zero_bytes = num_bytes - num_consumed_bytes;
            std::memset((char*)destination + num_consumed_bytes, 0, num_zero_bytes);
        }
    }
}
        
#ifdef __cplusplus
extern "C" {
#endif

        
uint8_t GPS_driver_obtain_current_position(uint8_t * position_as_bytes, uint8_t * hmac_as_bytes) {
    unsigned int position_as_bytes_length = 12/*Provide the size of the position_as_bytes buffer*/;
    ConsumeDataAndFillRestWithZeros(position_as_bytes, position_as_bytes_length);
    unsigned int hmac_as_bytes_length = 64/*Provide the size of the hmac_as_bytes buffer*/;
    ConsumeDataAndFillRestWithZeros(hmac_as_bytes, hmac_as_bytes_length);
    uint8_t cifuzz_var_0 = fdp->ConsumeIntegral<uint8_t>();
    return cifuzz_var_0;
}
        
uint8_t HSM_get_random_byte() {
    uint8_t cifuzz_var_1 = fdp->ConsumeIntegral<uint8_t>();
    return cifuzz_var_1;
}
        
int driver_get_current_time() {
    int cifuzz_var_2 = fdp->ConsumeIntegral<int>();
    return cifuzz_var_2;
}
        
uint8_t third_party_library_calc_hmac(const uint8_t * message, int len, const char * key, const char * nonce, uint8_t * hmac) {
    unsigned int hmac_length = 64/*Provide the size of the hmac buffer*/;
    ConsumeDataAndFillRestWithZeros(hmac, hmac_length);
    uint8_t cifuzz_var_3 = fdp->ConsumeIntegral<uint8_t>();
    return cifuzz_var_3;
}
        

#ifdef __cplusplus
}
#endif        
        
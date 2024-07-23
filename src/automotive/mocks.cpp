
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "crypto_1.h"
#include "gps_1.h"
#include "key_management_1.h"
#include "time_1.h"

#ifdef __cplusplus
}
#endif

static FuzzedDataProvider *gFDP;

// This function received the fuzzer generated data from the fuzz target.
// It needs to be called at the beginning of the LLVMFuzzerTestOneInput
// function.
void SetFDP(FuzzedDataProvider *fuzzed_data_provider) {
  gFDP = fuzzed_data_provider;
}

FuzzedDataProvider *GetFDP() { return gFDP; }

// Wrapper function for FuzzedDataProvider.h
// Writes |num_bytes| of input data to the given destination pointer. If there
// is not enough data left, writes all remaining bytes and fills the rest with
// zeros. Return value is the number of bytes written.
void ConsumeDataAndFillRestWithZeros(void *destination, size_t num_bytes) {
  if (destination != nullptr) {
    size_t num_consumed_bytes = GetFDP()->ConsumeData(destination, num_bytes);
    if (num_bytes > num_consumed_bytes) {
      size_t num_zero_bytes = num_bytes - num_consumed_bytes;
      std::memset((char *)destination + num_consumed_bytes, 0, num_zero_bytes);
    }
  }
}

#ifdef __cplusplus
extern "C" {
#endif

int driver_get_current_time() {
  int cifuzz_var_0 = GetFDP()->ConsumeIntegral<int>();
  return cifuzz_var_0;
}

uint8_t GPS_driver_obtain_current_position(uint8_t *position_as_bytes,
                                           uint8_t *hmac_as_bytes) {
  unsigned int position_as_bytes_length = 12;
  ConsumeDataAndFillRestWithZeros((void *)position_as_bytes,
                                  position_as_bytes_length);
  unsigned int hmac_as_bytes_length = 64;
  ConsumeDataAndFillRestWithZeros((void *)hmac_as_bytes, hmac_as_bytes_length);
  uint8_t cifuzz_var_1 = GetFDP()->ConsumeIntegral<uint8_t>();
  return cifuzz_var_1;
}

uint8_t HSM_get_random_byte() {
  uint8_t cifuzz_var_2 = GetFDP()->ConsumeIntegral<uint8_t>();
  return cifuzz_var_2;
}

uint8_t third_party_library_calc_hmac(const uint8_t *message, int len,
                                      const char *key, const char *nonce,
                                      uint8_t *hmac) {
  unsigned int hmac_length = 64;
  ConsumeDataAndFillRestWithZeros((void *)hmac, hmac_length);
  uint8_t cifuzz_var_3 = GetFDP()->ConsumeIntegral<uint8_t>();
  return cifuzz_var_3;
}

#ifdef __cplusplus
}
#endif

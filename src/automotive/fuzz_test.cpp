
#include <stddef.h>
#include <stdint.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "crypto_1.h"
#include "crypto_2.h"
#include "gps_1.h"
#include "key_management_1.h"
#include "time_1.h"

#ifdef __cplusplus
}
#endif

void SetFDP(FuzzedDataProvider *fuzzed_data_provider);
FuzzedDataProvider *GetFDP();
void ConsumeDataAndFillRestWithZeros(void *destination, size_t num_bytes);

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {

  // Ensure a minimum data length
  if (size < 100)
    return;

  // Setup FuzzedDataProvider and initialize the mocklib
  FuzzedDataProvider fdp(data, size);
  SetFDP(&fdp);

  int number_of_functions = GetFDP()->ConsumeIntegralInRange<int>(1, 100);
  for (int i = 0; i < number_of_functions; i++) {
    int function_id = GetFDP()->ConsumeIntegralInRange<int>(0, 15);
    switch (function_id) {

    case 0: {
      crypto_get_state();
      break;
    }

    case 1: {
      get_destination_position();
      break;
    }

    case 2: {
      crypto_key key = {};
      ConsumeDataAndFillRestWithZeros(key.key, 64);

      crypto_verify_key(key);
      break;
    }

    case 3: {
      current_time();
      break;
    }

    case 4: {
      crypto_nonce nonce_tmp = {};
      ConsumeDataAndFillRestWithZeros(nonce_tmp.nonce, 64);
      nonce_tmp.time_of_creation = GetFDP()->ConsumeIntegral<int>();
      crypto_nonce *nonce = &nonce_tmp;

      crypto_verify_nonce(nonce);
      break;
    }

    case 5: {
      std::vector<uint8_t> message_vec = GetFDP()->ConsumeBytes<uint8_t>(
          sizeof(uint8_t) * GetFDP()->ConsumeIntegral<uint16_t>());
      const uint8_t *message = (const uint8_t *)message_vec.data();

      // The parameter "len" seems to represent the length of a buffer/array. In
      // this case, we usually don't want to provide fuzzer-generated lengths
      // that differ from the actual length of the buffer. If you confirm that
      // the parameter is a length parameter, you can get the length of the
      // fuzzer-generated buffer as follows (replace "buffer" with the actual
      // variable):
      //     int len = buffer.size();
      int len = message_vec.size();
      crypto_hmac hmac_tmp = {};
      ConsumeDataAndFillRestWithZeros(hmac_tmp.hmac, 64);
      crypto_hmac *hmac = &hmac_tmp;

      crypto_verify_hmac(message, len, hmac);
      break;
    }

    case 6: {
      crypto_nonce nonce = {};
      ConsumeDataAndFillRestWithZeros(nonce.nonce, 64);
      nonce.time_of_creation = GetFDP()->ConsumeIntegral<int>();

      crypto_set_nonce(nonce);
      break;
    }

    case 7: {
      std::vector<uint8_t> message_vec = GetFDP()->ConsumeBytes<uint8_t>(
          sizeof(uint8_t) * GetFDP()->ConsumeIntegral<uint16_t>());
      const uint8_t *message = (const uint8_t *)message_vec.data();

      // The parameter "len" seems to represent the length of a buffer/array. In
      // this case, we usually don't want to provide fuzzer-generated lengths
      // that differ from the actual length of the buffer. If you confirm that
      // the parameter is a length parameter, you can get the length of the
      // fuzzer-generated buffer as follows (replace "buffer" with the actual
      // variable):
      //     int len = buffer.size();
      int len = message_vec.size();
      crypto_hmac hmac_tmp = {};
      ConsumeDataAndFillRestWithZeros(hmac_tmp.hmac, 64);
      crypto_hmac *hmac = &hmac_tmp;

      crypto_calculate_hmac(message, len, hmac);
      break;
    }

    case 8: {
      GPS_position position = {};
      position.longitude_degree = GetFDP()->ConsumeIntegral<uint8_t>();
      position.longitude_minute = GetFDP()->ConsumeIntegral<uint8_t>();
      position.longitude_second = GetFDP()->ConsumeIntegral<uint8_t>();
      position.latitude_degree = GetFDP()->ConsumeIntegral<uint8_t>();
      position.latitude_minute = GetFDP()->ConsumeIntegral<uint8_t>();
      position.latitude_second = GetFDP()->ConsumeIntegral<uint8_t>();

      set_destination_postition(position);
      break;
    }

    case 9: {
      crypto_key key = {};
      ConsumeDataAndFillRestWithZeros(key.key, 64);

      crypto_set_key(key);
      break;
    }

    case 10: {
      GPS_position position_tmp = {};
      position_tmp.longitude_degree = GetFDP()->ConsumeIntegral<uint8_t>();
      position_tmp.longitude_minute = GetFDP()->ConsumeIntegral<uint8_t>();
      position_tmp.longitude_second = GetFDP()->ConsumeIntegral<uint8_t>();
      position_tmp.latitude_degree = GetFDP()->ConsumeIntegral<uint8_t>();
      position_tmp.latitude_minute = GetFDP()->ConsumeIntegral<uint8_t>();
      position_tmp.latitude_second = GetFDP()->ConsumeIntegral<uint8_t>();
      GPS_position *position = &position_tmp;

      get_current_position(position);
      break;
    }

    case 11: {
      init_crypto_module();
      break;
    }

    case 12: {
      std::vector<uint8_t> key_vec = GetFDP()->ConsumeBytes<uint8_t>(
          sizeof(uint8_t) * GetFDP()->ConsumeIntegral<uint16_t>());
      uint8_t *key = (uint8_t *)key_vec.data();

      // The parameter "length" seems to represent the length of a buffer/array.
      // In this case, we usually don't want to provide fuzzer-generated lengths
      // that differ from the actual length of the buffer. If you confirm that
      // the parameter is a length parameter, you can get the length of the
      // fuzzer-generated buffer as follows (replace "buffer" with the actual
      // variable):
      //     uint8_t length = buffer.size();
      uint8_t length = key_vec.size();

      key_management_create_key(key, length);
      break;
    }

    case 13: {
      std::vector<uint8_t> nonce_vec = GetFDP()->ConsumeBytes<uint8_t>(
          sizeof(uint8_t) * GetFDP()->ConsumeIntegral<uint16_t>());
      uint8_t *nonce = (uint8_t *)nonce_vec.data();

      // The parameter "length" seems to represent the length of a buffer/array.
      // In this case, we usually don't want to provide fuzzer-generated lengths
      // that differ from the actual length of the buffer. If you confirm that
      // the parameter is a length parameter, you can get the length of the
      // fuzzer-generated buffer as follows (replace "buffer" with the actual
      // variable):
      //     uint8_t length = buffer.size();
      uint8_t length = nonce_vec.size();

      key_management_create_nonce(nonce, length);
      break;
    }

    case 14: {
      crypto_init();
      break;
    }
    }
  }
}

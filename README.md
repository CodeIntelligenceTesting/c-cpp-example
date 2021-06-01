# automotive-fuzzing-example
For the demo:
- Initialize Project
- Create fuzz test for a function
- To compile it the "extern" functions need to be implemented for this use the scripts in fuzzing/auto-mock-fuzz:
- ```python3 gen_template.py /path_to_project/automotive-fuzzing-example/modules/*/src/*.c /path_to_project/automotive-fuzzing-example/modules/*/src/*.h```
- This will create two excel sheets. The Sheet called testgen_mocks.xlsx will contain information about the functions that are declared as extern
- Fill in the excel sheet like this:

| int GPS_driver_obtain_current_position(uint8_t * position_as_bytes, uint8_t * hmac_as_bytes)                              | return: RETURN_INT(int)     | position_as_bytes: WRITE_BYTES(12) | hmac_as_bytes: WRITE_BYTES(64) |                        |                       |
|---------------------------------------------------------------------------------------------------------------------------|-----------------------------|------------------------------------|--------------------------------|------------------------|-----------------------|
| int third_party_library_calc_hmac(uint8_t * const message, int len, char * const key, char * const nonce, uint8_t * hmac) | return: RETURN_INT(int)     | message: WRITE_BYTES(len)          | key: WRITE_BYTES(64)           | nonce: WRITE_BYTES(64) | hmac: WRITE_BYTES(64) |
| uint8_t HSM_get_random_byte()                                                                                             | return: RETURN_INT(uint8_t) |                                    |                                |                        |                       |
| int driver_get_current_time()                                                                                             | return: RETURN_INT(int)     |                                    |                                |                        |                       |
- Run the second script to generate the mocking library from this: 
- ```python3 gen_tests.py mocklib gen_template/testgen_mocks.xlsx ../mocks```
- This creates mocklib.h and mocklib.cpp in fuzzing/mocks
- Add the mocklib.cpp to the compiler options and also add the include path fuzzing/mocks
- In the fuzztest you need to create a FuzzedDataProvider object and give a pointer to it to the mocking library. Add the following to the beginning of the FUZZ function:  
```FuzzedDataProvider fuzz_data(Data, Size);```  
```mocklib_set_data(&fuzz_data);```
- You also need to include the FuzzedDataProvider.h and mocklib.h in the fuzztest
- Now the fuzz test can run
- To create a fuzz test for all the functions fill in the excel sheet testgen_functions.xlsx like this:  

| enum crypto_return_status crypto_calculate_hmac(const uint8_t * message, int len, crypto_hmac * hmac) | message: ARG_DATA()                    | len: ARG_SIZE()    | hmac: ARG_STRUCT_PTR(crypto_hmac) |   |
|-------------------------------------------------------------------------------------------------------|----------------------------------------|--------------------|-----------------------------------|---|
| enum crypto_return_status crypto_set_key(crypto_key key)                                              | key: ARG_STRUCT(crypto_key)            |                    |                                   |   |
| enum crypto_return_status crypto_set_nonce(crypto_nonce nonce)                                        | nonce: ARG_STRUCT(crypto_nonce)        |                    |                                   |   |
| enum crypto_return_status crypto_verify_hmac(const uint8_t * message, int len, crypto_hmac * hmac)    | message: ARG_DATA()                    | len: ARG_SIZE()    | hmac: ARG_STRUCT_PTR(crypto_hmac) |   |
| enum crypto_return_status crypto_verify_key(crypto_key key)                                           | key: ARG_STRUCT(crypto_key)            |                    |                                   |   |
| enum crypto_return_status crypto_verify_nonce(crypto_nonce * nonce)                                   | nonce: ARG_STRUCT_PTR(crypto_nonce)    |                    |                                   |   |
| uint8_t * generate_random_bytes(uint8_t * buffer, uint8_t length)                                     | buffer: ARG_DATA()                     | length: ARG_SIZE() |                                   |   |
| enum GPS_return_status get_current_position(GPS_position * position)                                  | position: ARG_STRUCT_PTR(GPS_position) |                    |                                   |   |
| void key_management_create_key(uint8_t * key, uint8_t length)                                         | key: ARG_DATA()                        | length: ARG_SIZE() |                                   |   |
| void key_management_create_nonce(uint8_t * nonce, uint8_t length)                                     | nonce: ARG_DATA()                      | length: ARG_SIZE() |                                   |   |
| enum GPS_return_status set_destination_postition(GPS_position position)                               | position: ARG_STRUCT(GPS_position)     |                    |                                   |   |
| enum crypto_state crypto_get_state()                                                                  |                                        |                    |                                   |   |
| void crypto_init()                                                                                    |                                        |                    |                                   |   |
| GPS_position get_destination_position()                                                               |                                        |                    |                                   |   |
| enum GPS_return_status init_crypto_module()                                                           |                                        |                    |                                   |   |
| int time_current_time()                                                                               |                                        |                    |                                   |   |
- Then generate the fuzz test with the following command:
- ```python3 gen_tests.py fuzztests gen_template/testgen_functions.xlsx .```  
- This will create a file fuzztest.c. Copy its content to your own fuzztest
- Include crypto_module_types.h and GPS_module_types.h in the fuzztest
- Run the fuzztest



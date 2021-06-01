# automotive-fuzzing-example
For the demo:
- Initialize Project
- Create Fuzz Test for a function
- To compile it the "extern" functions need to be implemented for this use the scripts in fuzzing/auto-mock-fuzz:
- ```python3 gen_template.py /path_to_project/automotive-fuzzing-example/modules/*/src/*.c /path_to_project/automotive-fuzzing-example/modules/*/src/*.h```
- This will create two excel sheets. The Sheet called testgen_mocks.xlsx will contain information about the functions that are declared as extern
- Fill in the excel sheet like this:

| return: RETURN_INT(int)     | position_as_bytes: WRITE_BYTES(12) | hmac_as_bytes: WRITE_BYTES(64) |                        |                       |
|-----------------------------|------------------------------------|--------------------------------|------------------------|-----------------------|
| return: RETURN_INT(int)     | message: WRITE_BYTES(len)          | key: WRITE_BYTES(64)           | nonce: WRITE_BYTES(64) | hmac: WRITE_BYTES(64) |
| return: RETURN_INT(uint8_t) |                                    |                                |                        |                       |
| return: RETURN_INT(int)     |                                    |                                |                        |                       |

- Run the second script to generate the mocking library from this: 
- ```python3 gen_tests.py mocklib gen_template/testgen_mocks.xlsx ../mocks```
- This creates mocklib.h and mocklib.cpp in fuzzing/mocks
- Add the mocklib.cpp to the compiler options and also add the include path fuzzing/mocks
- In the fuzztest you need to create a FuzzedDataProvider object and give a pointer to it to the mocking library. Add the following to the beginning of the FUZZ function:  
```FuzzedDataProvider fuzz_data(Data, Size);```  
```mocklib_set_data(&fuzz_data);```
- You also need to include the FuzzedDataProvider.h and mocklib.h in the fuzztest

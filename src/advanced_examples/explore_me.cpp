#include <cstring>
#include <zlib.h>
#include <iostream>
#include "explore_me.h"

static long insecureEncrypt(long input);
static void trigger_double_free();

void ExploreStructuredInputChecks(InputStruct inputStruct){
    if (inputStruct.c == "Attacker") {
        if (insecureEncrypt(inputStruct.a) == 0x4e9e91e6677cfff3L) {
            if (insecureEncrypt(inputStruct.b) == 0x4f8b9fb34431d9d3L) {
                trigger_double_free();
            }
        }
    }

    return;
}

void ExploreCompressedInputChecks(const uint8_t *Data, size_t Size){
    uint8_t Uncompressed[100];
      size_t UncompressedLen = sizeof(Uncompressed);
      // Check if uncompression was successful
      if (Z_OK != uncompress(Uncompressed, &UncompressedLen, Data, Size)) {
          // Uncompression was not successfull
          // Just return and throw input away
          return;
      }
      if (UncompressedLen < 2) return;
      if (Uncompressed[0] == 'C' && Uncompressed[1] == 'I') {
          trigger_double_free();
      }
}

void ExploreSlowInputsChecks(int a, int b){
    if (a == 48664131) {
        for (int i = 0; i < b; i++) {
            if (i % 100'000'000 == 0) {
                std::cerr   << "In loop at position: " 
                            << std::to_string(i) 
                            << " of " 
                            << std::to_string(b) 
                            << std::endl;
            }
        }
    }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

static void trigger_double_free(){
    auto *buffer = static_cast<char *>(malloc(6));
    memcpy(buffer, "hello", 5);
    buffer[5] = '\0';
    for (int i = 0; i < 2; i++) {
        free(buffer);
    }
    buffer = 0;
}

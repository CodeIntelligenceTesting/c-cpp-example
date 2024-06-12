#include <cstring>

#include "explore_me.h"

static long insecureEncrypt(long input);
static void trigger_global_buffer_overflow(const std::string &c);
static void trigger_use_after_free();
static void trigger_double_free();
static void trigger_memory_leak();

void ExploreSimpleChecks(int a, int b, std::string c) {
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a < 100000) {
        if (c == "Attacker") {
          trigger_global_buffer_overflow(c);
        }
      }
    }
  }
}

void ExploreStructuredInputChecks(InputStruct inputStruct){
    if (inputStruct.c == "Attacker") {
        if (insecureEncrypt(inputStruct.a) == 0x4e9e91e6677cfff3L) {
            if (insecureEncrypt(inputStruct.b) == 0x4f8b9fb34431d9d3L) {
                trigger_double_free();
            }
        }
    }
}

void ExploreCustomMutatorExampleChecks(SpecialRequirementsStruct* specialRequirementsStruct){
    printf("Hello!\n");
    strncpy(specialRequirementsStruct->c, "Hello\0", specialRequirementsStruct->c_size);

    if (insecureEncrypt(specialRequirementsStruct->a) == 0x4e9e91e6677cfff3L) {
        if (insecureEncrypt(specialRequirementsStruct->b) == 0x4f8b9fb34431d9d3L) {
            trigger_memory_leak();
        }
    }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

char gBuffer[5] = {0};

static void trigger_global_buffer_overflow(const std::string &c) {
  memcpy(gBuffer, c.c_str(), c.length());
  printf("%s\n", gBuffer);
}

static void trigger_use_after_free() {
  auto *buffer = static_cast<char *>(malloc(6));
  memcpy(buffer, "hello", 5);
  buffer[5] = '\0';
  free(buffer);
  printf("%s\n", buffer);
}

static void trigger_double_free(){
    auto *buffer = static_cast<char *>(malloc(6));
    memcpy(buffer, "hello", 5);
    buffer[5] = '\0';
    for (int i = 0; i < 2; i++) {
        free(buffer);
    }
}

static void trigger_memory_leak(){
    auto *buffer = static_cast<char *>(malloc(6));
    memcpy(buffer, "hello", 5);
    buffer[5] = '\0';
    }
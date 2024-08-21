#include <cstring>

#include "explore_me.h"
#include "utils.h"

static long insecureEncrypt(long input);
static void trigger_global_buffer_overflow(const std::string &c);
static void trigger_use_after_free();
static long trigger_stack_exhaustion(long a);

void FunctionOne(int a, int b, std::string c) {
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

void FunctionTwo(long a, long b, char* c, size_t size) {
    if (a >= 20000) {
        // Trap that can trigger an unimportant finding that's caused by a faulty fuzz test.
        memcpy(c, "hello", std::min(static_cast<long>(5), static_cast<long>(size)));
        c[std::min(static_cast<long>(6), std::max(static_cast<long>(size)-1, 0L))] = '\0';
        if (b >= 2000000) {
            if (b - a < 100000) {
                trigger_stack_exhaustion(a);
            }
        }
    }
}

void FunctionThree(struct InputStruct inputStruct) {
    if (inputStruct.a >= 20000) {
        if (inputStruct.b >= 2000000) {
            if (inputStruct.b - inputStruct.a < 100000) {
                if (inputStruct.c == "Attacker") {
                    trigger_use_after_free();
                }
            }
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

static long trigger_stack_exhaustion(long a) {
    if (a > 0) {
        return trigger_stack_exhaustion(a-1) * 2;
    }

    return 1;
}
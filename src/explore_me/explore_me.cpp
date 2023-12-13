#include <stdexcept>

#include "explore_me.h"
#include "utils.h"

static void mustNeverBeCalled();
static long insecureEncrypt(long input);

void ExploreSimpleChecks(int a, int b, std::string c) {
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a < 100000) {
        if (c == "Attacker") {
          mustNeverBeCalled();
        }
      }
    }
  }
}

void ExploreComplexChecks(long a, long b, std::string c) {
  if (EncodeBase64(c) == "SGV5LCB3ZWw=") {
    if (insecureEncrypt(a) == 0x4e9e91e6677cfff3L) {
      if (insecureEncrypt(b) == 0x4f8b9fb34431d9d3L) {
        mustNeverBeCalled();
      }
    }
  }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

static void mustNeverBeCalled() {
  throw std::runtime_error("This function must never be called!");
}
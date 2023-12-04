#include "stack_buffer_overflow.h"
#include <cstring>
#include <cstdio>

void update_entry(char* entry) {
    strcpy(entry, "too long");
    printf("%s\n", entry);
}

void stack_buffer_overflow(int a, int b, std::string c) {
  if (a > 100 && b < 100 && c == "CODE INTELLIGENCE") {
    char s[1];
    update_entry(s);
  }
}

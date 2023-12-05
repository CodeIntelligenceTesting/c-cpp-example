//
// Created by philip on 04/12/23.
//

#include <string.h>
#include "bit_shifts.h"

long someBitShiftFunction(long inputOne, int shiftingDistance) {
    if (inputOne<<shiftingDistance == 84880000000 && inputOne+shiftingDistance < 81359) {
        char test[1];
        strcpy(test, "123");
    }

    return inputOne<<shiftingDistance;

}
#include <cifuzz/cifuzz.h>
#include <cstdlib>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <zlib.h>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreCompressedInputChecks, HI) {
    uint8_t uncompressed[3];
    size_t uncompressedLen = sizeof(uncompressed);
    uncompressed[0] = 'H';
    uncompressed[1] = 'I';
    uncompressed[2] = '\0';
    uint8_t compressed[3];
    size_t compressedLen = sizeof(compressed);
    if (Z_OK != compress(compressed, &compressedLen, uncompressed, uncompressedLen)) {
        abort();
    }
    EXPECT_NO_THROW(ExploreCompressedInputChecks(compressed, compressedLen));
}

TEST(ExploreCompressedInputChecks, HO) {
    uint8_t uncompressed[3];
    size_t uncompressedLen = sizeof(uncompressed);
    uncompressed[0] = 'H';
    uncompressed[1] = 'O';
    uncompressed[2] = '\0';
    uint8_t compressed[3];
    size_t compressedLen = sizeof(compressed);
    if (Z_OK != compress(compressed, &compressedLen, uncompressed, uncompressedLen)) {
        abort();
    }
    EXPECT_NO_THROW(ExploreCompressedInputChecks(compressed, compressedLen));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
    ExploreCompressedInputChecks(data, size);
}

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/**
Custom mutator example. In this case we only print out once that we are in a custom mutator and then use te regular one,
but you can also change the Data how you like. Make sure to return the new length.
*/
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t maxSize, unsigned int seed) {

    static bool printed;
    if (!printed) {
        std::cerr << "In custom mutator.\n";
        printed = true;
    }

    uint8_t uncompressed[100];
    size_t uncompressedLen = sizeof(uncompressed);
    size_t compressedLen = maxSize;
    if (Z_OK != uncompress(uncompressed, &uncompressedLen, data, size)) {
        // The data didn't uncompress.
        // So, it's either a broken input and we want to ignore it,
        // or we've started fuzzing from an empty corpus and we need to supply
        // out first properly compressed input.
        uint8_t dummy[] = {'H', 'i'};
        if (Z_OK != compress(data, &compressedLen, dummy, sizeof(dummy))) {
            return 0;
        } else {
            // fprintf(stderr, "Dummy: max %zd res %zd\n", MaxSize, CompressedLen);
            return compressedLen;
        }
    }

    uncompressedLen = LLVMFuzzerMutate(uncompressed, uncompressedLen, sizeof(uncompressed));
    if (Z_OK != compress(data, &compressedLen, uncompressed, uncompressedLen)) {
        return 0;
    }
    // make sure to return the new Size (that needs to be <= MaxSize) as return value!
    return compressedLen;
}

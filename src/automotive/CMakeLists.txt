add_library(automotive
    crypto/crypto_1.c
    crypto/crypto_2.c
    gps/gps_1.c
    key_management/key_management_1.c
    time/time_1.c
)

target_include_directories(automotive PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/gps
    ${CMAKE_CURRENT_SOURCE_DIR}/key_management
    ${CMAKE_CURRENT_SOURCE_DIR}/time
)
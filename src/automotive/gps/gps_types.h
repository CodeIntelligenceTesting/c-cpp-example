#ifndef GPS_MODULE_TYPES_H
#define GPS_MODULE_TYPES_H

#include <stdint.h>

typedef struct GPS_position {
  uint8_t longitude_degree;
  uint8_t longitude_minute;
  uint8_t longitude_second;
  uint8_t latitude_degree;
  uint8_t latitude_minute;
  uint8_t latitude_second;
} GPS_position;

enum GPS_return_status {
  GPS_success,
  GPS_failure,
};

#endif
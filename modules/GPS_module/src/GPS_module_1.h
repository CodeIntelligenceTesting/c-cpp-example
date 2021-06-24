#ifndef GPS_MODULE_1_H
#define GPS_MODULE_1_H

#include "GPS_module_types.h"

extern uint8_t GPS_driver_obtain_current_position(uint8_t * position_as_bytes, uint8_t * hmac_as_bytes);

enum GPS_return_status init_crypto_module();

enum GPS_return_status set_destination_postition(GPS_position position);

GPS_position get_destination_position();

enum GPS_return_status get_current_position(GPS_position * position);

#endif
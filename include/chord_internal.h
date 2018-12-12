#ifndef _LIBCHORD_INT_H
#define _LIBCHORD_INT_H
#include "chord.h"

time_t time_start;
unsigned long int w_start = 0;
unsigned long int w_atm = 0;
unsigned long int p_start = 0;
unsigned long int p_atm = 0;
time_t atm;
size_t read_b;
size_t write_b;
uint32_t steps_reg;
uint32_t steps_reg_find;

chord_node_t null_node = { .id = 0,
                          .size = 0,
                          .used = 0
                        };

#ifndef RIOT
struct timeval tout = { .tv_sec = 1, .tv_usec = 0 };
#endif
#endif

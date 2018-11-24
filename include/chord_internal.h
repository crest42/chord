#ifndef _LIBCHORD_INT_H
#define _LIBCHORD_INT_H
#include "chord.h"
#include "msg_handler.h"

time_t time_start;
time_t atm;
size_t read_b;
size_t write_b;

struct chord_callbacks cc = { .ping_handler = handle_ping,
                              .exit_handler = handle_exit,
                              .find_successor_handler = handle_find_successor,
                              .get_predecessor_handler = handle_get_predecessor,
                              .notify_handler = handle_notify,
                              .register_child_handler = handle_register_child,
                              .refresh_child_handler = handle_refresh_child,
                              .get_handler = NULL,
                              .put_handler = NULL,
                              .sync_handler = NULL,
                              .sync_fetch_handler = NULL };

struct chord_callbacks *get_callbacks(void) {
  return &cc;
}

chord_node_t null_node = { .id = 0,
                          .size = 0,
                          .used = 0
                        };

#ifndef RIOT
struct timeval tout = { .tv_sec = 1, .tv_usec = 0 };
#endif
#endif

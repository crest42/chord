#ifndef _LIBCHORD_INT_H
#define _LIBCHORD_INT_H
#include "chord.h"
struct node mynode;
struct node_additional my_additional;
struct node predecessor;
struct fingertable_entry fingertable[FINGERTABLE_SIZE];
struct node successorlist[SUCCESSORLIST_SIZE];
struct childs childs;
struct aggregate stats;
struct hooks hooks;

time_t start;
time_t atm;
size_t read_b;
size_t write_b;

struct hooks*
get_hooks(void)
{
  return &hooks;
}

struct aggregate *get_stats(void) {
  return &stats;
}

struct node*
get_own_node(void)
{
  return &mynode;
}

struct childs*
get_childs(void)
{
  return &childs;
}

struct fingertable_entry*
get_fingertable(void)
{
  return fingertable;
}

struct node*
get_successorlist(void)
{
  return successorlist;
}

// euclidean mod because -1 % n should be n-1 not 1
static int
mod(int a, int b)
{
  return ((a % b) + b) % b;
}

struct chord_callbacks cc = { .ping_handler = handle_ping,
                              .exit_handler = handle_exit,
                              .find_successor_handler = handle_find_successor,
                              .get_predecessor_handler = handle_get_predecessor,
                              .notify_handler = handle_notify,
                              .register_child_handler = handle_register_child,
                              .refresh_child_handler = handle_refresh_child,
                              .get_handler = NULL,
                              .put_handler = NULL };

struct chord_callbacks *get_callbacks(void) {
  return &cc;
}

struct node null_node = { .id = 0,
                          .additional = NULL };

#ifndef RIOT
struct timeval tout = { .tv_sec = 1, .tv_usec = 0 };
#endif
#endif

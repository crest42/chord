#ifndef _LIBCHORD_INT_H
#define _LIBCHORD_INT_H
#include "chord.h"
struct node mynode;
struct node predecessor;
struct fingertable_entry fingertable[FINGERTABLE_SIZE];
struct node successorlist[SUCCESSORLIST_SIZE];

nodeid_t pnodes[CHORD_RING_BITS];
struct node*
get_own_node(void)
{
  return &mynode;
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
                              .get_handler = NULL,
                              .put_handler = NULL };

struct chord_callbacks *get_callbacks(void) {
  return &cc;
}

struct key* first_key;
struct key* last_key;

struct node null_node = { .id = 0,
                          .socket = 0,
                          .successor = NULL,
                          .predecessor = NULL };

struct timeval tout = { .tv_sec = 3, .tv_usec = 0 };
#endif

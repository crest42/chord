#ifndef _LIBCHORD_INT_H
#define _LIBCHORD_INT_H
#include "chord.h"
struct node mynode;
struct node predecessor;
struct fingertable_entry fingertable[FINGERTABLE_SIZE];
struct node successorlist[SUCCESSORLIST_SIZE];

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

static bool
in_interval_id(int start, int end, int test)
{
  return (mod((test - start), CHORD_RING_SIZE) <=
          mod((end - start), CHORD_RING_SIZE));
}

static bool
in_interval(struct node* first, struct node* second, nodeid_t id)
{
  if (!first || !second) {
    return false;
  }
  // We need this because everything is in between x and x
  if (first->id == second->id) {
    return true;
  }
  return in_interval_id(first->id, second->id, id);
}

struct chord_callbacks cc = { .ping_handler = handle_ping,
                              .find_successor_handler = handle_find_successor,
                              .get_predecessor_handler = handle_get_predecessor,
                              .notify_handler = handle_notify,
                              .get_handler = NULL,
                              .put_handler = NULL };

struct key* first_key;
struct key* last_key;
#endif

#ifndef _LIBCHORD_INT_H
#define _LIBCHORD_INT_H
#include "chord.h"
struct node mynode;
struct node predecessor;
struct fingertable_entry fingertable[FINGERTABLE_SIZE];
struct node successorlist[SUCCESSORLIST_SIZE];


struct node *get_own_node(void) {
    return &mynode;
}
#endif

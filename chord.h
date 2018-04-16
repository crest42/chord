#ifndef _LIBCHORD_H
#define _LIBCHORD_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stddef.h>

FILE *default_out;
enum log_level
{
  OFF = 0x0,
  FATAL = 0x1,
  ERROR = 0x3,
  WARN = 0x7,
  INFO = 0xf,
  DEBUG = 0x1f,
  TRACE = 0x3f,
  ALL = 0xff
};

#define DEBUG_MAX_FUNC_NAME 20
#ifdef DEBUG_ENABLE
  #include <time.h>
  #include <stdarg.h>
  #include <stdio.h>
  #ifdef RIOT
    #include "thread.h"
    #define __FUNCTION__ ""
  #endif
  #ifndef DEBUG_LEVEL
    #define DEBUG_LEVEL INFO
  #endif
  #define DEBUG(level, ...) debug_printf((unsigned long)time(NULL),__FUNCTION__,level, __VA_ARGS__)
#else
  #define DEBUG(...) {}
  #define DEBUG_LEVEL OFF
#endif

typedef uint16_t nodeid_t;
#ifndef bool
    typedef int bool;
    #define true 1
    #define false 0
#endif

#ifdef RIOT
#define _getpid() thread_getpid()
#else
#include <sys/types.h>
#include <sys/syscall.h>
#define _getpid() (int)syscall(__NR_gettid)
#endif

#define HASH_DIGEST_SIZE 20
#ifdef CHORD_DEV
  #define CHORD_RING_BITS (8)
#endif
#ifndef CHORD_RING_BITS
  #define CHORD_RING_BITS (16)
#endif
#define FINGERTABLE_SIZE CHORD_RING_BITS
#define SUCCESSORLIST_SIZE CHORD_RING_BITS
#define CHORD_PORT (6667)
#define CHORD_OK (0)
#define CHORD_ERR (-1)
#define CHORD_PERIODIC_SLEEP (2)
#define CHORD_RING_SIZE (1<<CHORD_RING_BITS)


#define CHORD_MSG_COMMAND_SLOT (0)
#define CHORD_MSG_COMMAND_SIZE (sizeof(chord_msg_t))
#define CHORD_MSG_SRC_ID_SIZE (sizeof(nodeid_t))
#define CHORD_MSG_SRC_ID_SLOT (CHORD_MSG_COMMAND_SLOT + CHORD_MSG_COMMAND_SIZE)
#define CHORD_MSG_DST_ID_SIZE (sizeof(nodeid_t))
#define CHORD_MSG_DST_ID_SLOT (CHORD_MSG_SRC_ID_SLOT + CHORD_MSG_SRC_ID_SIZE)
#define CHORD_MSG_LENGTH_SIZE (sizeof(size_t))
#define CHORD_MSG_LENGTH_SLOT (CHORD_MSG_DST_ID_SLOT + CHORD_MSG_DST_ID_SIZE)
#define CHORD_HEADER_SIZE (CHORD_MSG_COMMAND_SIZE + CHORD_MSG_LENGTH_SIZE + CHORD_MSG_DST_ID_SIZE + CHORD_MSG_SRC_ID_SIZE)
#define CHORD_MSG_MAX_CONTENT_SIZE (MAX_MSG_SIZE-CHORD_HEADER_SIZE)

#define MAX_MSG_SIZE 512

enum msg_type
{
    MSG_TYPE_NULL                       = 0,
    MSG_TYPE_FIND_SUCCESSOR             = 1,
    MSG_TYPE_FIND_SUCCESSOR_RESP        = 2,
    MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT   = 3,
    MSG_TYPE_GET_PREDECESSOR            = 4,
    MSG_TYPE_GET_PREDECESSOR_RESP       = 5,
    MSG_TYPE_GET_PREDECESSOR_RESP_NULL  = 6,
    MSG_TYPE_GET_SUCCESSOR              = 7,
    MSG_TYPE_GET_SUCCESSOR_RESP         = 8,
    MSG_TYPE_PING                       = 9,
    MSG_TYPE_PONG                       = 10,
    MSG_TYPE_NOTIFY                     = 11,
    MSG_TYPE_NO_WAIT                    = 12,
    MSG_TYPE_COPY_SUCCESSORLIST         = 13,
    MSG_TYPE_COPY_SUCCESSORLIST_RESP    = 14,
    MSG_TYPE_CHORD_ERR                  = 15
};

typedef enum msg_type chord_msg_t;
struct node
{
    nodeid_t id;
    int socket;
    struct sockaddr_in6 addr;
    struct node *successor;
    struct node *predecessor;
};

struct fingertable_entry {
    nodeid_t start;
    nodeid_t interval;
    struct node node;
};
struct node *create_node(char *address);
struct node *get_own_node(void);

int find_successor(struct node *node, struct node *ret, nodeid_t id);
int hash(unsigned char *out, const char *in,size_t in_size,size_t out_size);
int init_chord(const char *node_addr);
int add_node(struct node *node);
/**
* \brief Join a node into a chord network.
* This function try to send a chord join to a known member in the ring.
* @param src node which wants to join
* @return CHORD_OK if everything is fine CHORD_ERR otherwise
*/
int join(struct node *src, struct node *target);
/**
* \brief Notify a node n' that we now consider it our successor.
* This is needed because n' may want to select us as his new predecessor.
*
* @param src node which wants to join
* @return CHORD_OK if everything is fine CHORD_ERR otherwise
*/
int notify(struct node *target);
void *thread_wait_for_msg(void *n);
void *thread_periodic(void *n);

/**
* Prints informations about a node, like it's id and it's successor and predecessor
*
* @param verbose also print successorlist and fingertable
*/
void debug_print_node(struct node *node,bool verbose);

/**
* Finds out if a node is consideret as null
* @param node node to check
* @return true is node id null, false otherwise
*/
bool node_is_null(struct node *node);

#endif

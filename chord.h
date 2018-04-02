#ifndef _LIBCHORD_H
#define _LIBCHORD_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h>
#ifdef DEBUG_ENABLE
#define DEBUG(...) printf(__VA_ARGS__)
#else
#define DEBUG(...) {}
#endif

typedef uint16_t nodeid_t;
#ifndef bool
    typedef int bool;
    #define true 1
    #define false 0
#endif

#ifndef HASH_DIGEST_SIZE
#define HASH_DIGEST_SIZE 20
#endif

#ifndef CHORD_RING_BITS
#define CHORD_RING_BITS (4)
#endif

#ifndef FINGERTABLE_SIZE
#define FINGERTABLE_SIZE CHORD_RING_BITS
#endif

#ifndef CHORD_PORT
#define CHORD_PORT (6667)
#endif
#define CHORD_ERR (-1)
#define CHORD_OK (0)
#define CHORD_BACKLOG_SIZE (10)
#define CHORD_PERIODIC_SLEEP (5)
#define CHORD_MSG_COMMAND_SLOT (0)
#define CHORD_MSG_COMMAND_SIZE (sizeof(chord_msg_t))
#define CHORD_MSG_SRC_ID_SIZE (sizeof(nodeid_t))
#define CHORD_MSG_SRC_ID_SLOT (CHORD_MSG_COMMAND_SLOT + CHORD_MSG_COMMAND_SIZE)
#define CHORD_MSG_DST_ID_SIZE (sizeof(nodeid_t))
#define CHORD_MSG_DST_ID_SLOT (CHORD_MSG_SRC_ID_SLOT + CHORD_MSG_SRC_ID_SLOT)
#define CHORD_MSG_LENGTH_SIZE (4)
#define CHORD_MSG_LENGTH_SLOT (CHORD_MSG_DST_ID_SLOT + CHORD_MSG_DST_ID_SIZE)
#define CHORD_HEADER_SIZE (CHORD_MSG_COMMAND_SIZE + CHORD_MSG_LENGTH_SIZE + CHORD_MSG_DST_ID_SIZE + CHORD_MSG_SRC_ID_SIZE)
#define CHORD_MSG_MAX_CONTENT_SIZE (MAX_MSG_SIZE-CHORD_HEADER_SIZE)
#define CHORD_RING_SIZE (1<<CHORD_RING_BITS)
#define CHORD_GET_PREDECESSOR_RESP_SIZE CHORD_RING_SIZE
#define CHORD_GET_SUCCESSOR_RESP_SIZE (sizeof(nodeid_t))
#define CHORD_FIND_SUCCESSOR_SIZE (sizeof(nodeid_t))
#define CHORD_PING_SIZE (sizeof(nodeid_t))
#define CHORD_FIND_SUCCESSOR_RESP_SIZE (sizeof(struct node))
#define MAX_MSG_SIZE 256
    enum msg_type
    {
        MSG_TYPE_FIND_SUCCESSOR = 1,
        MSG_TYPE_FIND_SUCCESSOR_RESP = 2,
        MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT = 3,
        MSG_TYPE_GET_PREDECESSOR = 4,
        MSG_TYPE_GET_PREDECESSOR_RESP = 5,
        MSG_TYPE_GET_PREDECESSOR_RESP_NULL = 6,
        MSG_TYPE_GET_SUCCESSOR = 7,
        MSG_TYPE_GET_SUCCESSOR_RESP = 8,
        MSG_TYPE_PING = 9,
        MSG_TYPE_PONG = 10,
        MSG_TYPE_NOTIFY = 11,
        MSG_TYPE_NO_WAIT = 12
    };
typedef enum msg_type chord_msg_t;
struct node
{
    unsigned char hash_id[HASH_DIGEST_SIZE];
    nodeid_t id;
    int socket;
    struct sockaddr_in6 addr;
    struct node *successor;
    struct node *predecessor;
};

struct fingertable_entry {
    nodeid_t start;
    nodeid_t interval;
    struct node *node;
};
struct key
{
    unsigned char id[HASH_DIGEST_SIZE];
    struct node *successor;
    struct node *predecessor;
};
static struct node mynode;
struct fingertable_entry fingertable[FINGERTABLE_SIZE];
struct node *find_successor(struct node *node, nodeid_t id);

int hash(unsigned char *out, const char *in,size_t in_size,size_t out_size);
int init_chord(const char *node_addr, size_t addr_size);
int add_node(struct node *node);
struct node *create_node(char *address);
struct node *get_own_node();
void *thread_wait_for_msg(void *n);
void *thread_periodic(void *n);
int notify(struct node *target);
nodeid_t join(struct node *src, struct node *target);

static int get_mod_of_hash(unsigned char *hash,int modulo) {
    int remainder = 0;
    for (int i = 0;  i < HASH_DIGEST_SIZE; ++i)
    {
        remainder = (remainder * 10 + hash[i]) % modulo;
    }
    return remainder;
}
#endif

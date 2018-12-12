/**
 * @file chord.h
 * @author Robin Lösch
 * @date 18 Apr 2018
 * @brief Function and type definitions for the chord protocoll
 *
 * @see http://nms.csail.mit.edu/papers/chord.pdf
 * @see https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf
 */
#ifndef _LIBCHORD_H
#define _LIBCHORD_H
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#define CHORD_TREE_ENABLED (true)                 /*!< True if node should construct tree */
#define CHORD_CHANGE_ID (true)                    /*!< True if node should choose a dynamic id */
#define HASH_DIGEST_SIZE (20)                     /*!< Size of the Hash Digest 20 for SHA1 */
#define CHORD_RING_BITS (16)                      /*!< Size of the chord ring in bits */
#define FINGERTABLE_SIZE CHORD_RING_BITS          /*!< Size of the fingertable */
#define SUCCESSORLIST_SIZE CHORD_RING_BITS        /*!< Size of the successorlist */
#define CHORD_PORT (6667)                         /*!< Default Listening udp port for chord */
#ifdef CHORD_TREE_ENABLED
  #define CHORD_TREE_CHILDS (2)                     /*!< Branching factor of the Tree Construction*/
  #define CHORD_TREE_ROOT (CHORD_RING_SIZE/2)       /*!< Root of the Tree Construction. The node witch own this is the root node*/
  #define CHORD_CHILD_TIMEOUT (3)                   /*!< Time after a child register msg until a child is considered timeouted */
#endif
#define CHORD_OK (0)                              /*!< Return this on success*/
#define CHORD_ERR (-1)                            /*!< Return this on failure*/
#define CHORD_PERIODIC_SLEEP (2)                  /*!< How long should a nodes thread sleep after a periodic run?*/
#define CHORD_RING_SIZE (1 << CHORD_RING_BITS)    /*!< Total size of the Ring*/
#define CHORD_MSG_COMMAND_SLOT (0)                /*!< Position of Header Field for chord command type */
#define CHORD_MSG_COMMAND_SIZE (sizeof(uint32_t)) /*!< Size of the Header Field for Chord cmd */
#define CHORD_MSG_SRC_ID_SLOT (CHORD_MSG_COMMAND_SLOT + CHORD_MSG_COMMAND_SIZE)
#define CHORD_MSG_SRC_ID_SIZE (sizeof(uint32_t))
#define CHORD_MSG_DST_ID_SIZE (sizeof(uint32_t))
#define CHORD_MSG_DST_ID_SLOT (CHORD_MSG_SRC_ID_SLOT + CHORD_MSG_SRC_ID_SIZE)
#define CHORD_MSG_LENGTH_SIZE (sizeof(uint32_t))
#define CHORD_MSG_LENGTH_SLOT (CHORD_MSG_DST_ID_SLOT + CHORD_MSG_DST_ID_SIZE)
#define CHORD_HEADER_SIZE                                                      \
  (CHORD_MSG_COMMAND_SIZE + CHORD_MSG_LENGTH_SIZE + CHORD_MSG_DST_ID_SIZE +    \
   CHORD_MSG_SRC_ID_SIZE)
#define MAX_MSG_SIZE (CHORD_HEADER_SIZE + SUCCESSORLIST_SIZE * sizeof(chord_node_t))
#define CHORD_MSG_MAX_CONTENT_SIZE (MAX_MSG_SIZE - CHORD_HEADER_SIZE)


#ifdef RIOT
#include "net/sock/udp.h"
#define TIMEOUT_DEF (2*US_PER_SEC)
#define TIMEOUT(y) (y*US_PER_SEC)
#define CHORD_YIELD(...) thread_yield()
#else
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#define TIMEOUT(y) (y)
#define TIMEOUT_DEF (2)
#define CHORD_YIELD(...) {}
#endif

typedef enum log_level
{
  OFF = 0x0,
  FATAL = 0x1,
  ERROR = 0x3,
  WARN = 0x7,
  INFO = 0xf,
  DEBUG = 0x1f,
  TRACE = 0x3f,
  ALL = 0xff
} chord_log_level_t;

/** Defines if DEBUG Function and macros should be enabled. */
#ifdef DEBUG_ENABLE
#include <errno.h>
#include <stdio.h>

void
debug_printf(unsigned long t,
             const char* fname,
             chord_log_level_t level,
             const char* format,
             ...);
char*
msg_to_string(int msg);
#define DEBUG(level, ...)                                                      \
  debug_printf((unsigned long)time(NULL), __func__, level, __VA_ARGS__)
#else
#define DEBUG(...)                                                             \
  {}
#define DEBUG_LEVEL OFF
#endif

typedef uint32_t nodeid_t;

#ifdef RIOT
#define _getpid() thread_getpid()
#else
#include <sys/syscall.h>
#define _getpid() (int)syscall(__NR_gettid)
#endif

/**
 * \brief Possible Message Types
 *
 * A Chord message always consists of a header and a payload
 * The First sizeof(msg_type) bytes in our header defined which type our message
 * has
 */
typedef enum msg_type
{
  MSG_TYPE_CHORD_ERR = -1, /*!< Error return type for failed requests */
  MSG_TYPE_NULL = 0,
  MSG_TYPE_FIND_SUCCESSOR = 1,           /*!< FIND_SUCCESSOR for given id */
  MSG_TYPE_FIND_SUCCESSOR_LINEAR = 2,
  MSG_TYPE_GET_PREDECESSOR = 3,      /*!< GET_PREDECESSOR of the target node*/
  MSG_TYPE_GET_SUCCESSOR = 4,
  MSG_TYPE_PING = 5, /*!< Check if node is alive */
  MSG_TYPE_PONG = 6,
  MSG_TYPE_NOTIFY = 7,  /*!< Notify successor that we may be the predecessor */
  MSG_TYPE_COPY_SUCCESSORLIST = 8,      /*!< Request to copy successorlist */
  MSG_TYPE_GET = 9,
  MSG_TYPE_PUT = 10,
  MSG_TYPE_REGISTER_CHILD = 11,
  MSG_TYPE_REFRESH_CHILD = 12,
  MSG_TYPE_REFRESH_CHILD_OK = 13,
  MSG_TYPE_SYNC = 14,
  MSG_TYPE_PUSH = 15,
  MSG_TYPE_GET_SUCCESSORLIST_ID = 16,
  MSG_TYPE_EXIT = 17,
  MSG_TYPE_SYNC_REQ_FETCH = 18,
  MSG_TYPE_FIND_SUCCESSOR_RESP = 64,      /*!< Response to FIND_SUCCESSOR */
  MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT = 65, /*!< Next node we need to ask  */
  MSG_TYPE_GET_PREDECESSOR_RESP = 66, /*!< Response to GET_PREDECESSOR */
  MSG_TYPE_GET_PREDECESSOR_RESP_NULL = 67, /*!< NULL Response to GET_PRE */
  MSG_TYPE_GET_SUCCESSOR_RESP = 68,
  MSG_TYPE_NO_WAIT = 69, /*!< Dummy Type which indicated one-shot */
  MSG_TYPE_COPY_SUCCESSORLIST_RESP = 70, /*!< Response which holds suc. list */
  MSG_TYPE_EXIT_ACK = 71,
  MSG_TYPE_PUT_ACK = 72,
  MSG_TYPE_PUT_EFAIL = 73,
  MSG_TYPE_GET_RESP = 74,
  MSG_TYPE_GET_EFAIL = 75,
  MSG_TYPE_REGISTER_CHILD_OK = 76,
  MSG_TYPE_REGISTER_CHILD_EFULL = 77,
  MSG_TYPE_REGISTER_CHILD_EWRONG = 78,
  MSG_TYPE_REGISTER_CHILD_REDIRECT = 79,
  MSG_TYPE_REFRESH_CHILD_REDIRECT = 80,
  MSG_TYPE_GET_SUCCESSORLIST_ID_RESP = 81,
  MSG_TYPE_GET_SUCCESSORLIST_ID_EFAIL = 82,
  MSG_TYPE_SYNC_REQ_RESP = 83,
  MSG_TYPE_SYNC_REQ_FETCH_OK = 85
} chord_msg_t;

typedef enum chord_role
{
  CHORD_ROLE_ACTIVE   = 0, /*!< Able to storage as well as retrieve and insert data*/
  CHORD_ROLE_STANDBY  = 1, /*!< Only store and retrieve data but not inserting*/
  CHORD_ROLE_EXTERNAL = 2, /*!< Only retrieve and insert but no storage */
} chord_role_t;

/**
 * \brief A definition of a node
 *
 * A Node is a member of the ring
 */
typedef struct node
{
  nodeid_t id; /*!< Id of the node. The node id is the hashed ipv6 address of
                  the node modulo the ring size */
  uint32_t size;
  uint32_t used;
  struct in6_addr addr;
} chord_node_t;

typedef struct node_additional {
  chord_node_t *successor;   /*!< Pointer to our successor node. */
  chord_node_t *predecessor; /*!< Pointer to our predecessor node */
} chord_node_additional_t;

#ifdef RIOT
struct socket_wrapper {
  sock_udp_t sock;
  sock_udp_ep_t remote;
  sock_udp_ep_t local;
  bool any;
};
#else
struct socket_wrapper {
  int sock;
  struct sockaddr_in6 local;
  struct sockaddr_in6 remote;
  bool any;
};
#endif

typedef struct aggregate {
  uint32_t nodes;
  uint32_t available;
  uint32_t used;
} chord_aggregation_t;

struct child
{
  nodeid_t parent;
  nodeid_t child;
  int i;
  time_t t;
  chord_node_t parent_suc;
  chord_aggregation_t aggregation;
};

#ifdef CHORD_TREE_ENABLED
struct childs
{
  struct child child[CHORD_TREE_CHILDS];
};
#endif

/**
 * \brief An Entry in our fingertable.
 *
 * The Fingertable is a "shortcut" through the ring, which allows us to query
 * nodes in O(log n) instead of O(n)
 */
struct fingertable_entry
{
  nodeid_t start;    /*!< Startpoint of the finger. */
  nodeid_t interval; /*!< Size of the Interval. End is start+interval */
  chord_node_t node;  /*!< Pointer to a node who is the successor of end */
};

typedef int(*chord_periodic_hook)(void *);

typedef struct hooks {
  chord_periodic_hook periodic_hook;
  void* periodic_data;
} chord_hooks_t;

/**
 * \brief Set up a node struct from a given address
 *
 * @param address Target ipv6 address of the node we want to create
 * @param node Return parameter where the node is saved needs to be pre
 * allocated
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
create_node(char *address, chord_node_t *node);

chord_hooks_t*
get_hooks(void);

chord_aggregation_t *get_stats(void);

chord_node_t *get_own_node(void);

chord_node_t *get_successor(void);

chord_node_t *get_predecessor(void);

/**
 * \brief Finds and returns the successor of a given Chord ring
 *
 * This functions walks around our ring until it finds the successor of a given
 * id. A successor if a id is the next node which has a id greater or equal the
 * provided id
 *
 * @param node Node to ask for the successor
 * @param Return parameter where to successor of @id is provided. Needs to be
 * allocated
 * @param id The id for which we need the successor
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
find_successor(chord_node_t *node, chord_node_t *ret, nodeid_t id);

/**
 * \brief Generates a hash. Implementation speicific
 *
 * This function needs to be implemented by the Application. The Hash function
 * can be any function which results are distributed evenly
 *
 * @param out Provided buffer which holds the generated hash
 * @param in Buffer which holds the data to be HASH_DIGEST_SIZE
 * @in_size Size of the input data
 * @out_size Size of the resulting hash in bytes
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
hash(/*@out@*/ unsigned char* out,
     const unsigned char* in,
     size_t in_size,
     size_t out_size);

/**
 * \brief Init the libary
 *
 * This function set up the chord ring.
 * E. g. generates the nodes which belongs to the application and init data
 * structures etc.
 *
 * @param Node_addr Node addr to listen
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
init_chord(const char* addr);

/**
 * \brief Starts the chord node
 *
 * This function either starts a new chord ring or try to join into an existing ring
 * This depends on if there is any content in the bootstrap list.
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
chord_start(void);

/**
 * \brief  Function which needs to be invoked by a thread answer requests from
 * other nodes
 *
 * Answer messages like get_successor and checks ring on incomming notify
 * messages
 *
 * @param n Own node which is setup by init_chord and can be fetched using
 * @get_own_node
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
/*@null@*/ void*
thread_wait_for_msg(void* n);

/**
 * \brief  Function which needs to be invoked by a thread to stabilize the
 * ring
 *
 * Stabilize the ring as needed by the chord protocoll and then sleeps
 * CHORD_PERIODIC_SLEEP seconds
 *
 * @param n Own node which is setup by init_chord and can be fetched
 * using @get_own_node
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
/*@null@*/ void*
thread_periodic(void* n);

/**
 * \brief Print informations about a node, like it's id, successor and
 * predecessor
 *
 * @param verbose also print successorlist and fingertable
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
void
debug_print_node(chord_node_t *node, bool verbose);

/**
 * \brief Returns the IDs of all nodes in the successorlist of a node
 *
 * @param target node to ask
 * @param id array of SUCCESSORLIST_SIZE nodeid_t elements to return the ids
 *
 * @return CHORD_OK on success, CHORD_ERR otherwise
 */
int
get_successorlist_id(chord_node_t *target, nodeid_t* id);

void
chord_mutex_lock(void);

void
chord_mutex_unlock(void);
#endif

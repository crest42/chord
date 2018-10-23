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
#include <unistd.h>

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

/** Defines if DEBUG Function and macros should be enabled. */
#ifdef DEBUG_ENABLE
#include <errno.h>
#include <stdio.h>
#include <time.h>

void
debug_printf(unsigned long t,
             const char* fname,
             enum log_level level,
             const char* format,
             ...);
char*
msg_to_string(int msg);
#define DEBUG(level, ...)                                                      \
  debug_printf((unsigned long)time(NULL), __FUNCTION__, level, __VA_ARGS__)
#else
#define DEBUG(...)                                                             \
  {}
#define DEBUG_LEVEL OFF
#endif

typedef uint32_t nodeid_t;

#ifndef bool
typedef int bool;
#define true 1
#define false 0
#endif

#ifdef RIOT
#define _getpid() thread_getpid()
#else
#include <sys/syscall.h>
#define _getpid() (int)syscall(__NR_gettid)
#endif

/** Size of the hash digest which gets generated by the hashs functions. 20 is
 * the digest size oh sha1.
 */
#define HASH_DIGEST_SIZE 20
#define CHORD_RING_BITS (16)
#define FINGERTABLE_SIZE CHORD_RING_BITS
#define SUCCESSORLIST_SIZE CHORD_RING_BITS
#define CHORD_PORT (6667)
#define CHORD_TREE_CHILDS (2)
#define CHORD_OK (0)
#define CHORD_ERR (-1)
#define CHORD_PERIODIC_SLEEP (2)
#define CHORD_RING_SIZE (1 << CHORD_RING_BITS)
#define CHORD_CHANGE_ID (1)
#define CHORD_CHANGE_INTERVAL (5)
#define CHORD_MSG_COMMAND_SLOT (0)
#define CHORD_MSG_COMMAND_SIZE (sizeof(chord_msg_t))
#define CHORD_MSG_SRC_ID_SIZE (sizeof(nodeid_t))
#define CHORD_MSG_SRC_ID_SLOT (CHORD_MSG_COMMAND_SLOT + CHORD_MSG_COMMAND_SIZE)
#define CHORD_MSG_DST_ID_SIZE (sizeof(nodeid_t))
#define CHORD_MSG_DST_ID_SLOT (CHORD_MSG_SRC_ID_SLOT + CHORD_MSG_SRC_ID_SIZE)
#define CHORD_MSG_LENGTH_SIZE (sizeof(size_t))
#define CHORD_MSG_LENGTH_SLOT (CHORD_MSG_DST_ID_SLOT + CHORD_MSG_DST_ID_SIZE)
#define CHORD_HEADER_SIZE                                                      \
  (CHORD_MSG_COMMAND_SIZE + CHORD_MSG_LENGTH_SIZE + CHORD_MSG_DST_ID_SIZE +    \
   CHORD_MSG_SRC_ID_SIZE)
#define CHORD_MSG_MAX_CONTENT_SIZE (MAX_MSG_SIZE - CHORD_HEADER_SIZE)

#define MAX_MSG_SIZE 1024

/**
 * \brief Possible Message Types
 *
 * A Chord message always consists of a header and a payload
 * The First sizeof(msg_type) bytes in our header defined which type our message
 * has
 */
enum msg_type
{
  MSG_TYPE_CHORD_ERR = -1, /*!< Error return type for failed requests */
  MSG_TYPE_NULL = 0,
  MSG_TYPE_FIND_SUCCESSOR = 1,           /*!< FIND_SUCCESSOR for given id */
  MSG_TYPE_FIND_SUCCESSOR_RESP = 2,      /*!< Response to FIND_SUCCESSOR */
  MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT = 3, /*!< Next node we need to ask  */
  MSG_TYPE_GET_PREDECESSOR = 4,      /*!< GET_PREDECESSOR of the target node*/
  MSG_TYPE_GET_PREDECESSOR_RESP = 5, /*!< Response to GET_PREDECESSOR */
  MSG_TYPE_GET_PREDECESSOR_RESP_NULL = 6, /*!< NULL Response to GET_PRE */
  MSG_TYPE_GET_SUCCESSOR = 7,
  MSG_TYPE_GET_SUCCESSOR_RESP = 8,
  MSG_TYPE_PING = 9, /*!< Check if node is alive */
  MSG_TYPE_PONG = 10,
  MSG_TYPE_NOTIFY = 11,  /*!< Notify successor that we may be the predecessor */
  MSG_TYPE_NO_WAIT = 12, /*!< Dummy Type which indicated one-shot */
  MSG_TYPE_COPY_SUCCESSORLIST = 13,      /*!< Request to copy successorlist */
  MSG_TYPE_COPY_SUCCESSORLIST_RESP = 14, /*!< Response which holds suc. list */
  MSG_TYPE_EXIT = 15,
  MSG_TYPE_EXIT_ACK = 16,
  MSG_TYPE_GET = 17,
  MSG_TYPE_PUT = 18,
  MSG_TYPE_PUT_ACK = 19,
  MSG_TYPE_GET_RESP = 20,
  MSG_TYPE_FIND_SUCCESSOR_LINEAR = 21,
  MSG_TYPE_REGISTER_CHILD = 22,
  MSG_TYPE_REGISTER_CHILD_OK = 23,
  MSG_TYPE_REGISTER_CHILD_EFULL = 24,
  MSG_TYPE_REGISTER_CHILD_EWRONG = 25,
  MSG_TYPE_REGISTER_CHILD_REDIRECT = 26,
  MSG_TYPE_REFRESH_CHILD = 27,
  MSG_TYPE_REFRESH_CHILD_OK = 28,
  MSG_TYPE_REFRESH_CHILD_REDIRECT = 29,
};
typedef enum msg_type chord_msg_t;


/**
 * \brief Nodes State for ID Transition
 *
 * @see http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.86.7648&rep=rep1&type=pdf
 */
enum node_state
{

  STATE_B = 0,
  STATE_F = 1,
  STATE_F_ASTERISK = 3,
  STATE_A = 4
};
typedef enum msg_type node_state_t;

/**
 * \brief A definition of a node
 *
 * A Node is a member of the ring
 */
struct node
{
  nodeid_t id; /*!< Id of the node. The node id is the hashed ipv6 address of
                  the node modulo the ring size */
  size_t size;
  size_t used;
  int socket; /*!< A Socket fd to the node or where we listen for incomming
                 messages. */
  struct sockaddr_in6 addr;
  struct node* successor;   /*!< Pointer to our successor node. */
  struct node* predecessor; /*!< Pointer to our predecessor node */
};

struct key
{
  nodeid_t id; /*!< Id of the key. The node id is the hashed ipv6 address of
                  the node modulo the ring size */
  nodeid_t owner;
  size_t size;
  unsigned char hash[20];
  unsigned char* data;
  struct key* next;
};

struct aggregate{
  int nodes;
  int available;
  int used;
};

struct child
{
  nodeid_t parent;
  nodeid_t child;
  int i;
  time_t t;
  struct node parent_suc;
  struct aggregate aggregation;
};

struct childs
{
  struct child child[CHORD_TREE_CHILDS];
};

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
  struct node node;  /*!< Pointer to a node who is the successor of end */
};

typedef int (*chord_callback)(chord_msg_t,
                              unsigned char*,
                              nodeid_t,
                              int,
                              struct sockaddr*,
                              size_t);
int
handle_ping(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size);

int
handle_exit(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size);
int
handle_find_successor(chord_msg_t type,
                      unsigned char* data,
                      nodeid_t src,
                      int sock,
                      struct sockaddr* src_addr,
                      size_t src_addr_size);

int
handle_get_predecessor(chord_msg_t type,
                       unsigned char* data,
                       nodeid_t src,
                       int sock,
                       struct sockaddr* src_addr,
                       size_t src_addr_size);

int
handle_notify(chord_msg_t type,
              unsigned char* data,
              nodeid_t src,
              int sock,
              struct sockaddr* src_addr,
              size_t src_addr_size);

int
handle_register_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size);

int
handle_refresh_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size);

struct chord_callbacks
{
  chord_callback ping_handler;
  chord_callback exit_handler;
  chord_callback find_successor_handler;
  chord_callback get_predecessor_handler;
  chord_callback notify_handler;
  chord_callback put_handler;
  chord_callback get_handler;
  chord_callback register_child_handler;
  chord_callback refresh_child_handler;
};

struct chord_callbacks*
get_callbacks(void);
struct key**
get_first_key(void);

int
chord_send_block_and_wait(struct node* target,
                          unsigned char* msg,
                          size_t size,
                          chord_msg_t wait,
                          unsigned char* buf,
                          size_t bufsize);

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
create_node(char* address, struct node* node);

/**
 * \brief Returns our own node
 *
 * @return node Our own node
 */
struct node*
get_own_node(void);

struct aggregate*
get_stats(void);

struct childs*
get_childs(void);

/**
 * \brief Returns fingertable
 *
 * @return fingertable_entry pointer to first fingertable entry
 */
struct fingertable_entry*
get_fingertable(void);

/**
 * \brief Returns successorlist
 *
 * @return Return pointer to first successorlist entry
 */
struct node*
get_successorlist(void);

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
find_successor(struct node* node, struct node* ret, nodeid_t id);

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
hash(unsigned char* out,
     const unsigned char* in,
     size_t in_size,
     size_t out_size);
int
get_mod_of_hash(unsigned char* hash, int modulo);
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
 * \brief Add a Node to out Chord Ring
 *
 * This functions add a node to our Chord ring
 *
 * @param node The node to add. If node is NULL we set up a new Ring.
 * Otherwise we try to join to the node provided
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
add_node(struct node* node);

/**
 * \brief Join a node into a chord network.
 *
 *  This function try to send a chord join to a known member in the ring.
 *
 * @param src node which wants to join
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
join(struct node* src, struct node* target);

/**
 * \brief Notify a node n' that we now consider it our successor.
 * This is needed because n' may want to select us as his new predecessor.
 *
 * @param src node which wants to join
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
int
notify(struct node* target);

/**
 * Function which needs to be invoked by a thread answer requests from other
 * nodes
 *
 * Answer messages like get_successor and checks ring on incomming notify
 * messages
 *
 * @param n Own node which is setup by init_chord and can be fetched using
 * @get_own_node
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
void*
thread_wait_for_msg(void* n);

/**
 * Function which needs to be invoked by a thread to stabilize the ring
 *
 * Stabilize the ring as needed by the chord protocoll and then sleeps
 * CHORD_PERIODIC_SLEEP seconds
 *
 * @param n Own node which is setup by init_chord and can be fetched
 * using @get_own_node
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
void*
thread_periodic(void* n);

/**
 * Print informations about a node, like it's id, successor and predecessor
 *
 * @param verbose also print successorlist and fingertable
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
void
debug_print_node(struct node* node, bool verbose);

/**
 * Finds out if a node is considered as null
 *
 * @param node node to check
 * @return true is node id null, false otherwise
 */
bool
node_is_null(struct node* node);

int
chord_send_nonblock_sock(int sock,
                         unsigned char* msg,
                         size_t size,
                         struct sockaddr* addr,
                         socklen_t addr_len);

                         int
remove_dead_node(nodeid_t id);


int
copy_node(struct node* node, struct node* copy);

bool
in_interval(struct node* first, struct node* second, nodeid_t id);

#endif

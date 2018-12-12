
/**
 * @file chord.c
 * @author Robin Lösch
 * @date 18 Apr 2018
 * @brief File implements the chord Protocol
 *
 * @see http://nms.csail.mit.edu/papers/chord.pdf
 * @see https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf
 */
#ifdef POSIX_SOCK
#define _GNU_SOURCE
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
extern pthread_mutex_t mutex;

#endif
#include "../include/chord.h"
#include "../include/chord_internal.h"
#include "../include/network.h"
#include "../include/bootstrap.h"
#include "../include/chord_util.h"
chord_node_t mynode, *self = &mynode;
chord_node_additional_t my_additional;
chord_node_t predecessor;
struct fingertable_entry fingertable[FINGERTABLE_SIZE];
chord_node_t successorlist[SUCCESSORLIST_SIZE];
#ifdef CHORD_TREE_ENABLED
  struct childs childs, *self_childs = &childs;
#endif
chord_aggregation_t stats, *mystats = &stats;
chord_hooks_t hooks;
struct bootstrap_list bslist;
chord_role_t role = CHORD_ROLE_ACTIVE;
unsigned char msg_buf[MAX_MSG_SIZE];
/* Static functions */
int steps = 1;

static int reset_fingertable(void) {
  nodeid_t start = 0;
  nodeid_t interval = 0;
  for (uint32_t i = 0; i < FINGERTABLE_SIZE; i++) {
    //TODO: Double Modulo?
    start = (mynode.id + ((1 << i) % CHORD_RING_SIZE)) % CHORD_RING_SIZE;
    interval =
      (mynode.id + ((1 << (i + 1)) % CHORD_RING_SIZE)) % CHORD_RING_SIZE;
    interval -= start;
    fingertable[i].start = start;
    fingertable[i].interval = interval;
  }
  return CHORD_OK;
}

static int set_nodeid(nodeid_t id) {
  assert(id > 0);
  assert(id <= (uint32_t)CHORD_RING_SIZE);
  self->id = id;
  return reset_fingertable();
}

static int
update_successorlist(chord_node_t *src)
{
  marshal_msg(MSG_TYPE_COPY_SUCCESSORLIST,
               src->id,
               sizeof(nodeid_t),
               (unsigned char*)(&(mynode.id)),
               msg_buf);
  chord_msg_t type =
    chord_send_block_and_wait(src,
                              msg_buf,
                              CHORD_HEADER_SIZE + sizeof(nodeid_t),
                              MSG_TYPE_COPY_SUCCESSORLIST_RESP,
                              (unsigned char*)(successorlist + 1),
                              (sizeof(successorlist) - sizeof(chord_node_t)),
                              NULL);
  if (type == MSG_TYPE_COPY_SUCCESSORLIST_RESP) {
    (void)memcpy(successorlist, src, sizeof(chord_node_t));
    return CHORD_OK;
  } else {
    DEBUG(DEBUG, "get msg type %s\n", msg_to_string(type));
    return CHORD_ERR;
  }
}

/**
 * \brief Join a node into a chord network.
 *
 *  This function try to send a chord join to a known member in the ring.
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
static int
join(chord_node_t *target)
{
  (void)memset(my_additional.predecessor, 0, sizeof(chord_node_t));
  if (find_successor(target, my_additional.successor, self->id) == CHORD_ERR) {
    return CHORD_ERR;
  }
  if (node_is_null(my_additional.successor)) {
    DEBUG(ERROR, "Unable to find successor exit\n");
    return CHORD_ERR;
  }
  DEBUG(INFO, "Update successorlist\n");
  update_successorlist(my_additional.successor);
  return CHORD_OK;
}

static int
request_predecessor(chord_node_t *target, chord_node_t *pre)
{
  marshal_msg(MSG_TYPE_GET_PREDECESSOR,
               target->id,
               0,
               NULL,
               msg_buf);
  chord_msg_t type =
    chord_send_block_and_wait(target,
                              msg_buf,
                              CHORD_HEADER_SIZE,
                              MSG_TYPE_GET_PREDECESSOR_RESP,
                              (unsigned char*)pre,
                              sizeof(chord_node_t),
                              NULL);
  if (type == MSG_TYPE_GET_PREDECESSOR_RESP) {
    return CHORD_OK;
  } else if (type == MSG_TYPE_GET_PREDECESSOR_RESP_NULL) {
    (void)memset(pre, 0, sizeof(chord_node_t));
    return CHORD_OK;
  } else {
    DEBUG(ERROR, "get msg type %s %d\n", msg_to_string(type), type);
    return CHORD_ERR;
  }
}

/* base-2 logarithm, rounding down */
static inline uint32_t lg_down(uint32_t x) {
  return 31U - __builtin_clzl(x);
}

/* base-2 logarithm, rounding up */
static inline uint32_t lg_up(uint32_t x) {
  return lg_down(x - 1) + 1;
}

static int tree_granularity(uint32_t l) {
  return 0;
  int x = l - lg_up(l) - 1;
  return (x < 0) ? 0 : x;
}

static bool nodes_share_n_bits(nodeid_t first, nodeid_t second, int bits) {
  assert(bits <= CHORD_RING_SIZE);
  nodeid_t mask =
    ((nodeid_t)__INT_MAX__) ^
    (nodeid_t)(((uint32_t)1 << (uint32_t)(CHORD_RING_BITS - bits)) - 1);
  if ((first & mask) == (second & mask)) {
    return true;
    }
    return false;
}

static nodeid_t get_share(chord_node_t *node, chord_node_t *successor) {
  assert(node != NULL);
  assert(successor != NULL);
  if (successor->id > node->id) {
    return successor->id - node->id;
  } else {
    return (CHORD_RING_SIZE - node->id) + successor->id;
  }
}

static nodeid_t find_splitnode(chord_node_t *target) {

  chord_node_t r, pre;
  (void)memset(&r, 0, sizeof(r));
  (void)memset(&pre, 0, sizeof(pre));
  int i = 0, set = 0;
  find_successor(target, &r, mynode.id);
  chord_node_t list[CHORD_RING_BITS];
  (void)memset(list, 0, sizeof(list));
  for (i = 0; i < CHORD_RING_BITS; i++) {
    if(i == 0) {
      find_successor(&r, &list[i], r.id);
      if(list[i].id == r.id) {
        break;
      }
    } else {
      find_successor(&r, &list[i], list[i-1].id);
      if(list[i].id == list[0].id) {
        break;
      }
    }
  }
  for (i = 0; i < CHORD_RING_BITS; i++) {
    if (list[i].id != 0 && nodes_share_n_bits(r.id,list[i].id,tree_granularity(CHORD_RING_BITS))) {
      set++;
    }
  }
  nodeid_t share;
  assert(CHORD_RING_BITS >= tree_granularity(CHORD_RING_BITS));
  if (set >= 1 << (uint32_t)(CHORD_RING_BITS - tree_granularity(CHORD_RING_BITS))) {
    request_predecessor(&r, &pre);
    if(pre.id < r.id) {
      share = r.id - pre.id;
    } else {
      share = (CHORD_RING_SIZE - pre.id) + r.id;
    }
    return r.id-(share/2);
  } else {
    nodeid_t max_share = 0;
    int max_id = 0;
    for (int i = 1; i < CHORD_RING_BITS; i++) {
      if(list[i].id == 0) {
        break;
      }
      chord_node_t *a, *b;
      if (i == 0) {
        a = &r;
        b = &list[0];
      } else {
        a = &list[i - 1];
        b = &list[i];
      }
      share = get_share(a, b);
      if (share >= max_share) {
        max_share = share;
        max_id = i;
      }
    }
    nodeid_t split;
    if (max_share == 0) {
      max_share = get_share(&r, &r);
      split = r.id;
    } else {
      split = list[max_id].id;
    }
    return split - (max_share / 2);
  }
}

static int
pop_successor(chord_node_t *next)
{
  int i = 0;
  do {
    copy_node(&successorlist[0], next);
    memmove(&successorlist[0],
           &successorlist[1],
           sizeof(successorlist) - sizeof(chord_node_t));
    (void)memset(&successorlist[SUCCESSORLIST_SIZE - 1], 0, sizeof(chord_node_t));
    i++;
  } while (node_is_null(next) &&
           i < SUCCESSORLIST_SIZE);
  return CHORD_OK;
}

static int
init_fingertable(void)
{
  reset_fingertable();
  for (int i = 0; i < FINGERTABLE_SIZE; i++) {
    (void)memset(&fingertable[i].node, 0, sizeof(chord_node_t));
  }
  return CHORD_OK;
}

static int init_successorlist(void) {
  (void)memset(successorlist, 0, sizeof(successorlist));
  return CHORD_OK;
}

static nodeid_t parent_function(nodeid_t id) {
  #ifdef CHORD_TREE_ENABLED
  int k = 2;
  nodeid_t alpha = (nodeid_t)CHORD_TREE_ROOT;
  int a = (id - alpha);
  if(a < 0 && a > -CHORD_RING_SIZE) {
    a = (((a%CHORD_RING_SIZE)+CHORD_RING_SIZE)%CHORD_RING_SIZE);
  } else {
    a = a % CHORD_RING_SIZE;
  }

  if (a >= 0 && a <= CHORD_TREE_ROOT) {
    return (alpha + (a/k)) % CHORD_RING_SIZE;
  } else if (a > CHORD_RING_SIZE / 2 && a <= CHORD_RING_SIZE) {
    return (alpha - ((CHORD_RING_SIZE - a) / k)) % CHORD_RING_SIZE;
  } else {
    assert(true);
    return CHORD_ERR;
  }
  #else
  (void)id;
  return CHORD_OK;
  #endif
}

/**
 * \brief Notify a node n' that we now consider it our successor.
 * This is needed because n' may want to select us as his new predecessor.
 *
 * @return CHORD_OK if everything is fine CHORD_ERR otherwise
 */
static int
notify(chord_node_t *target)
{
  if (!target) {
    DEBUG(ERROR, "notify target is NULL\n");
    return CHORD_ERR;
  }
  DEBUG(INFO, "Notify successor %d\n", target->id);
  marshal_msg(MSG_TYPE_NOTIFY,
               target->id,
               sizeof(chord_node_t),
               (unsigned char*)(&mynode),
               msg_buf);
  chord_msg_t type =
    chord_send_block_and_wait(target,
                              msg_buf,
                              CHORD_HEADER_SIZE + sizeof(chord_node_t),
                              MSG_TYPE_NO_WAIT,
                              NULL,
                              0,
                              NULL);
  if (type == MSG_TYPE_CHORD_ERR) {
    DEBUG(ERROR, "Error in notify returned msg type MSG_TYPE_CHORD_ERR\n");
    return CHORD_ERR;
  }
  return CHORD_OK;
}

static int
stabilize(chord_node_t *node)
{
  chord_node_t pre;
  int ret = CHORD_OK;
  if (!node_is_null(my_additional.successor)) {
    (void)memset(&pre, 0, sizeof(pre));
    ret = request_predecessor(my_additional.successor, &pre);
    DEBUG(INFO,
          "got pre %d\n",
          (int)pre.id);
    if(pre.id == mynode.id && memcmp(&pre.addr,&mynode.addr,sizeof(pre.addr)) != 0) {
      set_nodeid(find_splitnode(node));
      find_successor(node, my_additional.successor, mynode.id);
      return CHORD_ERR;
    }
    if (ret != CHORD_ERR) {
      if (!node_is_null(&pre)) {
        if (node->id != pre.id && in_interval(node, my_additional.successor, pre.id)) {
          DEBUG(INFO,
                "looks like me->suc->pre is new: %d old: %d me: %d\n",
                pre.id,
                my_additional.successor->id,
                mynode.id);
          if (pre.id != my_additional.successor->id) {
            copy_node(&pre, &fingertable[0].node);
            update_successorlist(my_additional.successor);
            DEBUG(INFO, "Update successor to %d\n", my_additional.successor->id);
          }
        } else {
          DEBUG(DEBUG, "looks like me->suc->pre stays the same\n");
        }
      } else {
        (void)memcpy(my_additional.predecessor, my_additional.successor, sizeof(chord_node_t));
      }
      if (!node_is_null(my_additional.successor) && role != CHORD_ROLE_EXTERNAL) {
        notify(my_additional.successor);
      }
    } else {
      DEBUG(ERROR, "Could not reach successor\n");
    }
  }
  return ret;
}

static bool
is_finger(chord_node_t *n, struct fingertable_entry* entry)
{
  if (!n || !entry) {
    return false;
  }
  if (entry->node.id > ((entry->start + entry->interval) % CHORD_RING_SIZE)) {
    if (n->id > (entry->start + entry->interval) && n->id < entry->node.id) {
      return true;
    }
  } else if (entry->node.id <
             ((entry->start + entry->interval) % CHORD_RING_SIZE)) {
    if (n->id < (entry->start + entry->interval) && n->id > entry->node.id) {
      return true;
    }
  }
  return false;
}

static void
fix_fingers(chord_node_t *node)
{
  // TODO: Not really sure if we want to ommit our successor.
  nodeid_t i = 0;
  do {
    i = (uint32_t)(rand() % CHORD_RING_BITS);
  } while (i == 0);
  struct fingertable_entry* f = &fingertable[i];

  DEBUG(INFO, "Fix finger %d\n", i);
  if (my_additional.successor != NULL && !node_is_null(my_additional.successor) &&
      (node->id != my_additional.successor->id)) {
    DEBUG(DEBUG,
          "Fix fingers find successor for %d ask: %d\n",
          f->start,
          my_additional.successor->id);

    nodeid_t id = ((f->start + f->interval) % CHORD_RING_SIZE);
    find_successor(node, &f->node, id);

    chord_node_t *save = &f->node;
    if (!node_is_null(save)) {
      while (i + 1 < FINGERTABLE_SIZE - 1 &&
             is_finger(&fingertable[i].node, &fingertable[i + 1])) {
        if (save->id != fingertable[i + 1].node.id) {
          DEBUG(DEBUG,
                "%d new: %d old: %d\n",
                i + 1,
                save->id,
                fingertable[i + 1].node.id);
          copy_node(save, &fingertable[i + 1].node);
        }
        i++;
      }
    } else {
      DEBUG(ERROR, "finger %d is null\n", i);
    }
  }
}

static bool
ping_node(chord_node_t *node)
{
  if (node_is_null(node)) {
    return false;
  }
  marshal_msg(MSG_TYPE_PING,
               node->id,
               sizeof(nodeid_t),
               (unsigned char*)(&(mynode.id)),
               msg_buf);
  nodeid_t retid = 0;
  chord_msg_t type =
    chord_send_block_and_wait(node,
                              msg_buf,
                              CHORD_HEADER_SIZE + sizeof(nodeid_t),
                              MSG_TYPE_PONG,
                              (unsigned char*)&retid,
                              sizeof(nodeid_t),
                              NULL);
  if (type == MSG_TYPE_PONG && retid == node->id) {
    return true;
  } else {
    return false;
  }
}

static bool
check_predecessor(void)
{
  DEBUG(INFO, "check pre %d\n", my_additional.predecessor->id);
  return ping_node(my_additional.predecessor);
}

static bool
check_successor(void)
{
  DEBUG(INFO, "check suc %d\n", my_additional.successor->id);
  return ping_node(my_additional.successor);
}

/*
static int
send_exit(chord_node_t *node, chord_node_t *update)
{
  marshal_msg(
    MSG_TYPE_EXIT, node->id, sizeof(chord_node_t), (unsigned char*)update, msg_buf);

  while (true) {
    chord_msg_t type =
      chord_send_block_and_wait(node,
                                msg_buf,
                                CHORD_HEADER_SIZE + sizeof(chord_node_t),
                                MSG_TYPE_EXIT_ACK,
                                NULL,
                                0,
                                NULL);
    if (type == MSG_TYPE_EXIT_ACK) {
      return CHORD_OK;
    } else {
      DEBUG(ERROR,
            "get msg type %s %d expected %d %d\n",
            msg_to_string(type),
            type,
            msg_to_string(MSG_TYPE_EXIT_ACK),
            MSG_TYPE_EXIT_ACK);
      return CHORD_ERR;
    }
  }
}*/

/*
static int
node_exit(chord_node_t *node)
{
  if (my_additional.successor && !node_is_null(my_additional.successor)) {
    chord_node_t *update;
    if (my_additional.predecessor && !node_is_null(my_additional.predecessor)) {
      update = my_additional.predecessor;
    } else {
      update = &null_node;
    }
    DEBUG(INFO,
          "send exit to successor %d. Update node is %d\n",
          node->additional->successor->id,
          update->id);
    send_exit(my_additional.successor, update);
  }
  if (my_additional.predecessor && !node_is_null(my_additional.predecessor)) {
    chord_node_t *update;
    if (my_additional.successor && !node_is_null(my_additional.successor)) {
      update = my_additional.successor;
    } else {
      update = &null_node;
    }
    DEBUG(INFO,
          "send exit to predeccessor %d. Update node is %d\n",
          my_additional.predecessor->id,
          update->id);

    send_exit(my_additional.predecessor, update);
  }
  return CHORD_OK;
}
*/

static bool in_sync(void) {
  if (!node_is_null(my_additional.successor) && !node_is_null(my_additional.predecessor)) {
    return true;
  }
  return false;
}

static bool is_root(chord_node_t *n, chord_node_t *pre) {
  #ifdef CHORD_TREE_ENABLED
  return in_interval(pre,n,(uint32_t)CHORD_TREE_ROOT - 1);
  #else
    (void)n;
    (void)pre;
    return false;
  #endif
}

static int get_parent(struct child *c) {
  c->parent = mynode.id;
  c->i = 0;
  do {
    nodeid_t tmp = c->parent;
    c->parent = parent_function(c->parent);
    DEBUG(DEBUG,"parent function for %d is %d\n", tmp, c->parent);
    if(tmp != c->parent) {
      c->i++;
    }
  } while (in_interval(my_additional.predecessor,&mynode,c->parent-1));
  return CHORD_OK;
}

static int register_child(struct child *c){
  #ifndef CHORD_TREE_ENABLED
    return CHORD_OK;
  #endif
  assert(c != NULL);
  struct child new;
  (void)memset(&new, 0, sizeof(new));
  if(get_parent(&new) != CHORD_OK) {
    DEBUG(ERROR, "Error in get_parent\n");
    return CHORD_ERR;
  }
  if(false && new.parent == c->parent) {
    return CHORD_OK;
  } else {
    c->parent = new.parent;
    c->i      = new.i;
  }
  chord_msg_t type = MSG_TYPE_CHORD_ERR;
  do {
    find_successor(my_additional.predecessor, &c->parent_suc, c->parent - 1);
  } while (c->parent_suc.id == self->id);
  steps_reg_find = steps;
  unsigned char ret[sizeof(chord_node_t) + sizeof(chord_aggregation_t)];
  steps_reg = 0;
  do {
  steps_reg++;
  DEBUG(INFO,
        "Register Child P^%d(%d) = %d on %d with size: %d and node: %d\n",
        c->i,
        self->id,
        c->parent,
        c->parent_suc.id,
        c->aggregation.available,
        c->aggregation.nodes);
  marshal_msg(MSG_TYPE_REGISTER_CHILD,
               c->parent_suc.id,
               sizeof(struct child),
               (unsigned char*)c,
               msg_buf);
  type = chord_send_block_and_wait(&c->parent_suc,
                                   msg_buf,
                                   CHORD_HEADER_SIZE + sizeof(struct child),
                                   MSG_TYPE_REGISTER_CHILD_OK,
                                   (unsigned char*)ret,
                                   sizeof(ret),
                                   NULL);
  (void)memcpy(&c->parent_suc, ret, sizeof(chord_node_t));
  } while (type == MSG_TYPE_REGISTER_CHILD_REDIRECT);
  if (type == MSG_TYPE_REGISTER_CHILD_OK) {
    (void)memcpy(&stats, ret + sizeof(chord_node_t), sizeof(chord_aggregation_t));
    return CHORD_OK;
  } else {
    c->parent = 0;
    DEBUG(DEBUG, "get msg type %s\n", msg_to_string(type));
    return type;
  }
}

static int refresh_parent(struct child *c) {
  #ifndef CHORD_TREE_ENABLED
    return CHORD_OK;
  #endif
  marshal_msg(MSG_TYPE_REFRESH_CHILD,
              c->parent_suc.id,
              sizeof(struct child),
              (unsigned char*)c,
              msg_buf);
  unsigned char ret[sizeof(chord_node_t) + sizeof(chord_aggregation_t)];
  chord_msg_t type =
    chord_send_block_and_wait(&c->parent_suc,
                              msg_buf,
                              CHORD_HEADER_SIZE + sizeof(struct child),
                              MSG_TYPE_REFRESH_CHILD_OK,
                              (unsigned char*)ret,
                              sizeof(ret),
                              NULL);
  (void)memcpy(&c->parent_suc, ret, sizeof(chord_node_t));
  (void)memcpy(&stats, (ret) + sizeof(chord_node_t), sizeof(chord_aggregation_t));
  if (type == MSG_TYPE_REFRESH_CHILD_REDIRECT) {
    register_child(c);
  } else if(type == MSG_TYPE_CHORD_ERR) {
    return CHORD_ERR;
  }
  return CHORD_ERR;
}

#ifdef DEBUG_ENABLE
static int get_nodes(void) {
  return stats.nodes;
}

static int get_used(void) {
  return stats.used;
}

static int get_size(void) {
  return stats.available;
}
#endif

static int aggregate(chord_aggregation_t *aggregation) {
  #ifdef CHORD_TREE_ENABLED

  uint32_t nodes = 0, available = 0, used = 0;
  struct childs* c = &childs;
  time_t systime = time(NULL);
  (void)memset(aggregation, 0, sizeof(chord_aggregation_t));
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if (c->child[i].child != 0 && (systime-(c->child[i].t)) <= 6) {
      uint32_t n = c->child[i].aggregation.nodes,
          a = c->child[i].aggregation.available,
          u = c->child[i].aggregation.used;
      (n > 0) ? nodes += n : nodes++;
      available += a;
      used += u;
    }
  }
  aggregation->nodes = ++nodes;
  aggregation->available = available + self->size;
  aggregation->used = used + self->used;
  return CHORD_OK;
  #else
  (void)aggregation;
  return CHORD_OK;
  #endif
}

static int
start(/*@NULL@*/ chord_node_t *node)
{
  if (node) {
    #ifdef CHORD_CHANGE_ID
      set_nodeid(find_splitnode(node));
    #endif

    for (int i = 1; i <= 3 && (join(node) == CHORD_ERR); i++) {
      DEBUG(ERROR,
            "Unable to join retry in %d seconds(%d/3)\n",
            CHORD_PERIODIC_SLEEP,
            i);
      sleep(CHORD_PERIODIC_SLEEP);
    }
  } else {
    #ifdef CHORD_CHANGE_ID
      set_nodeid((nodeid_t)(CHORD_RING_SIZE-1));
    #endif
    copy_node(&mynode, my_additional.successor);
    DEBUG(INFO, "Create new chord ring %d\n", my_additional.successor->id);
    for (int i = 0; i < FINGERTABLE_SIZE; i++) {
      if (i > 0) {
        copy_node(my_additional.successor, &fingertable[i].node);
      }
    }
    (void)memset(successorlist, 0, sizeof(successorlist));
  }

  return CHORD_OK;
}

/* Public functions */

chord_node_t *get_own_node(void) {
  return self;
}

chord_node_t *get_successor(void) {
  return my_additional.successor;
}

chord_node_t *get_predecessor(void) {
  return my_additional.predecessor;
}

chord_hooks_t *get_hooks(void) {
  return &hooks;
}

int chord_start(void) {
  if (bslist.curr > 0) {
    for (uint32_t i = 0; i < bslist.size;i++) {
      chord_node_t tmp = {.id = CHORD_RING_SIZE, .size = 0, .used  = 0};
      memcpy(&tmp.addr, &bslist.list[i], sizeof(tmp.addr));
      if(ping_node(&tmp) == CHORD_OK) {
        start(&tmp);
        break;
      }
    }
  } else {
    start(NULL);
  }
  return CHORD_OK;
}

int
init_chord(const char* local_addr)
{
  (void)memset(&mynode, 0, sizeof(mynode));
  (void)memset(&my_additional, 0, sizeof(my_additional));
  (void)memset(&predecessor, 0, sizeof(predecessor));
  #ifdef CHORD_TREE_ENABLED
  (void)memset(&childs, 0, sizeof(struct child));
  #endif
  (void)memset(&bslist, 0, sizeof(struct bootstrap_list));
  bslist.size = BSLIST_SIZE;
  time_start = time(NULL);
  if (addr_to_node(&mynode, local_addr) == CHORD_ERR) {
    DEBUG(ERROR, "Error while translating address %s to binary\n", local_addr);
    return CHORD_ERR;
  }

  unsigned char hash_id[HASH_DIGEST_SIZE];
  hash(hash_id,
       (unsigned char*)&(mynode.addr),
       sizeof(mynode.addr),
       HASH_DIGEST_SIZE);
  mynode.id = get_mod_of_hash(hash_id, CHORD_RING_SIZE);

  my_additional.predecessor = &predecessor;
  my_additional.successor = &fingertable[0].node;
 
  init_fingertable();
  init_successorlist();

  chord_aggregation_t *a = &stats;
  mynode.size = 1024;
  mynode.used = 0;
  a->used = 0;
  a->nodes = 0;

  hooks.periodic_hook = NULL;
  init_callbacks();
  set_callback(MSG_TYPE_PING, handle_ping);
  set_callback(MSG_TYPE_EXIT, handle_exit);
  set_callback(MSG_TYPE_FIND_SUCCESSOR, handle_find_successor);
  set_callback(MSG_TYPE_FIND_SUCCESSOR_LINEAR, handle_find_successor);
  set_callback(MSG_TYPE_GET_PREDECESSOR, handle_get_predecessor),
  set_callback(MSG_TYPE_NOTIFY, handle_notify);
  set_callback(MSG_TYPE_REGISTER_CHILD, handle_register_child);
  set_callback(MSG_TYPE_REFRESH_CHILD, handle_refresh_child);
  set_callback(MSG_TYPE_PUT, NULL);
  return CHORD_OK;
}

int
get_successorlist_id(chord_node_t *target, nodeid_t *id) {
  assert(target != NULL);
  marshal_msg(
      MSG_TYPE_GET_SUCCESSORLIST_ID, target->id, 0, NULL, msg_buf);
    chord_msg_t type =
      chord_send_block_and_wait(target,
                                msg_buf,
                                CHORD_HEADER_SIZE,
                                MSG_TYPE_GET_SUCCESSORLIST_ID_RESP,
                                (unsigned char*)id,
                                SUCCESSORLIST_SIZE*sizeof(nodeid_t),
                                NULL);
    if (type == MSG_TYPE_GET_SUCCESSORLIST_ID_RESP) {
      return CHORD_OK;
    } else {
      return CHORD_ERR;
    }
}

static int chord_find_successor(chord_node_t *target, chord_node_t *ret, nodeid_t id) {
  chord_node_t *final = NULL, *tmp = target;
  steps = 1;
  chord_msg_t query_type = MSG_TYPE_FIND_SUCCESSOR;
  DEBUG(INFO, "Start find successor ask: %d for %d\n", target->id, id);
  while (final == NULL) {
    DEBUG(INFO,"steps neeeded %d\n",(steps));
    //(void)memset(msg, 0, sizeof(msg)); // TODO Remove
    marshal_msg(
      query_type, tmp->id, sizeof(nodeid_t), (unsigned char*)&id, msg_buf);
    chord_msg_t type =
      chord_send_block_and_wait(tmp,
                                msg_buf,
                                CHORD_HEADER_SIZE + sizeof(nodeid_t),
                                MSG_TYPE_FIND_SUCCESSOR_RESP,
                                (unsigned char*)ret,
                                sizeof(chord_node_t),
                                NULL);
    if (type == MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT) {
      steps++;
      tmp = ret;
      DEBUG(INFO, "ask next node %d ask for %d\n", tmp->id, id);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_RESP) {
      if (ret->id == tmp->id) {
        final = ret;
        break;
      } else {
        tmp = ret;
      }
    } else if (type == MSG_TYPE_CHORD_ERR &&
               query_type == MSG_TYPE_FIND_SUCCESSOR) {
      query_type = MSG_TYPE_FIND_SUCCESSOR_LINEAR;
      tmp = target; // TODO: Only search starting from the last node
      DEBUG(INFO, "Start linear scan %d ask for %d\n", tmp->id, id);
    } else {
      DEBUG(ERROR, "unable to find successor for %d\n", id);
      return CHORD_ERR;
    }
  }

  nodeid_t ret_id = ret->id;
  if (ret_id == 0) {
    (void)memset(ret, 0, sizeof(chord_node_t));
    return CHORD_ERR;
  }
  DEBUG(INFO, "Found successor for %d on %d steps: %d\n", id, steps, ret->id);
  return CHORD_OK;
}

int
find_successor(chord_node_t *target, chord_node_t *ret, nodeid_t id)
{
  assert(id <= (nodeid_t)CHORD_RING_SIZE);
  if (!node_is_null(my_additional.predecessor) &&
      in_interval(my_additional.predecessor, self, id)) {
    copy_node(self,ret);
    return CHORD_OK;
  } else {
    return chord_find_successor(target, ret, id);
  }
}

int
create_node(char* address, chord_node_t *node)
{
  if (!address) {
    DEBUG(FATAL, "Error address is NULL in create node\n");
    return CHORD_ERR;
  }
  (void)memset(&node->addr, 0, sizeof(node->addr));

  int c = inet_pton(AF_INET6, address, &(node->addr));
  if (c != 1) {
    if (c == -1) {
      DEBUG(ERROR, "Error in inet_pton");
    } else if (c == 0) {
      DEBUG(FATAL, "Addr %s is not a valid IPv6 address\n", address);
    } else {
      DEBUG(FATAL, "Unknown error in inet_pton\n");
    }
    return CHORD_ERR;
  }

  unsigned char hash_id[HASH_DIGEST_SIZE];
  hash(hash_id,
       (unsigned char*)&node->addr,
       sizeof(node->addr),
       sizeof(hash_id));
  node->id = get_mod_of_hash(hash_id, CHORD_RING_SIZE);

  DEBUG(INFO, "create node with addr %s\n", address);

  return CHORD_OK;
}

/*@null@*/ void*
thread_wait_for_msg(void* n)
{

  if(role == CHORD_ROLE_EXTERNAL) {
    return NULL;
  }
  #ifdef POSIX_SOCK
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    struct rusage *usage = (struct rusage *)n;
    w_start = ts.tv_sec + ts.tv_nsec;
  #endif
  int iteration = 0;
  chord_node_t *node = self;
  struct socket_wrapper s;
  (void)memset(&s, 0, sizeof(s));
  s.any = true;
  if (sock_wrapper_open(&s, self, NULL, CHORD_PORT, 0) != 0) {
    DEBUG(ERROR,"Error while open new port\n");
    return NULL;
  }
  while (true) {
    #ifdef POSIX_SOCK
      pthread_mutex_lock (&mutex);
      timespec_get(&ts, TIME_UTC);
      w_atm = (ts.tv_sec*1000000000) + ts.tv_nsec;
      getrusage(RUSAGE_THREAD, usage);
      pthread_mutex_unlock (&mutex);
    #endif
    iteration++;
    DEBUG(INFO, "wait for message run %d\n", iteration);
    if (wait_for_message(node, &s) == CHORD_ERR) {
      DEBUG(ERROR, "error in wait_for_message\n");
    }
    CHORD_YIELD();
  }

  /*@notreached@*/
  return NULL;
}


/*@null@*/ void*
thread_periodic(void* n)
{
   #ifdef POSIX_SOCK
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    struct rusage *usage = (struct rusage *)n;
    p_start = ts.tv_sec + ts.tv_nsec;
  #endif
  int i = 0;
  chord_node_t *node = &mynode;
  struct child c;
  (void)memset(&c, 0, sizeof(c));
  while (true) {
   #ifdef POSIX_SOCK
      pthread_mutex_lock (&mutex);
      timespec_get(&ts, TIME_UTC);
      p_atm = (ts.tv_sec*1000000000) + ts.tv_nsec;
      getrusage(RUSAGE_THREAD, usage);
      pthread_mutex_unlock (&mutex);
    #endif
    atm = time(NULL);
    #ifdef DEBUG_ENABLE
    time_t runtime = atm - time_start;
    if(runtime > 1) {
      double read_s = read_b / runtime, write_s = write_b/runtime, overall_s = (read_b + write_b) / runtime;
      DEBUG(
        INFO,
        "runtime : %d, read: %d (%.2fb/s) write: %d (%.2fb/s) overall: %d (%.2fb/s)\n",
        runtime,
        read_b,
        read_s,
        write_b,
        write_s,
        read_b + write_b,
        overall_s);
    }
    #endif
    c.child = mynode.id;
    DEBUG(INFO, "%d: periodic run %d\n", node->id, i);
    assert(!node_is_null(my_additional.successor));
    assert(node->id > 0);
    i++;


    DEBUG(INFO, "Start stabilization Procedure\n");
    nodeid_t old = mynode.id;
    if (stabilize(node) == CHORD_OK) {
      if (!node_is_null(my_additional.successor)) {
        DEBUG(INFO, "Update successorlist\n");
        update_successorlist(my_additional.successor);
      }
    } else {
      if(old != mynode.id) {
        continue;
      }
      DEBUG(ERROR, "Error in stabilization Procedure: %d\n");
    }

    if (!node_is_null(my_additional.predecessor) && !check_predecessor()) {
      DEBUG(
        ERROR, "ERROR PRE %d Do not respond to ping\n", my_additional.predecessor->id);
      remove_dead_node(my_additional.predecessor->id);
      (void)memset(my_additional.predecessor, 0, sizeof(chord_node_t));
    }

    if (!node_is_null(my_additional.successor) && !check_successor()) {
      DEBUG(
        ERROR, "Error: suc %d do not respond to ping\n", my_additional.successor->id);
      remove_dead_node(my_additional.successor->id);
      pop_successor(my_additional.successor);
      DEBUG(INFO, "Update successor to %d\n", my_additional.successor->id);
    }
    if(role == CHORD_ROLE_EXTERNAL) {
      //TODO: Need to get size anyway
      continue;
    }


    DEBUG(INFO, "Aggregate Stats\n");
    aggregate(&c.aggregation);
    if (!is_root(&mynode, my_additional.predecessor)) {
      if (!node_is_null(my_additional.predecessor) && !node_is_null(my_additional.successor)) {
        register_child(&c);
      }
      if(!node_is_null(&c.parent_suc)) {
        if(refresh_parent(&c) == CHORD_ERR) {
          (void)memset(&c.parent_suc, 0, sizeof(chord_node_t));
        }
      }
    } else {
      (void)memcpy(&stats, &c.aggregation, sizeof(chord_aggregation_t));
      DEBUG(INFO,
            "root got %d nodes %d/%d used\n",
            get_nodes(),
            get_used(),
            get_size());
    }

    if (in_sync() && hooks.periodic_hook != NULL) {
      DEBUG(INFO, "Call periodic Hook\n");
      hooks.periodic_hook(hooks.periodic_data);
    }

    fix_fingers(node);

#ifdef DEBUG_ENABLE
    debug_print_node(node, false);
#endif
    sleep(CHORD_PERIODIC_SLEEP);
  }
  /*@notreached@*/
  return NULL;
}
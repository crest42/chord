
/**
 * @file chord.c
 * @author Robin Lösch
 * @date 18 Apr 2018
 * @brief File implements the chord Protocol
 *
 * @see http://nms.csail.mit.edu/papers/chord.pdf
 * @see https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf
 */

#include "../include/chord.h"
#include "../include/chord_internal.h"
#include "../include/network.h"


/* Static functions */

static int reset_fingertable(void) {
  nodeid_t start = 0;
  nodeid_t interval = 0;
  for (int i = 0; i < FINGERTABLE_SIZE; i++) {
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
  assert(id <= CHORD_RING_SIZE);
  struct node* mynode = get_own_node();
  mynode->id = id;
  return reset_fingertable();
}

static int
update_successorlist(struct node* src)
{
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshal_msg(MSG_TYPE_COPY_SUCCESSORLIST,
               src->id,
               sizeof(nodeid_t),
               (unsigned char*)(&(mynode.id)),
               msg);
  chord_msg_t type =
    chord_send_block_and_wait(src,
                              msg,
                              CHORD_HEADER_SIZE + sizeof(nodeid_t),
                              MSG_TYPE_COPY_SUCCESSORLIST_RESP,
                              (unsigned char*)(successorlist + 1),
                              (sizeof(successorlist) - sizeof(struct node)),
                              NULL);
  if (type == MSG_TYPE_COPY_SUCCESSORLIST_RESP) {
    memcpy(successorlist, src, sizeof(struct node));
    return CHORD_OK;
  } else {
    DEBUG(DEBUG, "get msg type %s\n", msg_to_string(type));
    return CHORD_ERR;
  }
  return CHORD_OK;
}


static int
get_predecessor(struct node* target, struct node* pre)
{
  unsigned char msg[CHORD_HEADER_SIZE];
  marshal_msg(MSG_TYPE_GET_PREDECESSOR,
               target->id,
               0,
               NULL,
               msg);
  chord_msg_t type =
    chord_send_block_and_wait(target,
                              msg,
                              CHORD_HEADER_SIZE,
                              MSG_TYPE_GET_PREDECESSOR_RESP,
                              (unsigned char*)pre,
                              sizeof(struct node),
                              NULL);
  if (type == MSG_TYPE_GET_PREDECESSOR_RESP) {
    return CHORD_OK;
  } else if (type == MSG_TYPE_GET_PREDECESSOR_RESP_NULL) {
    memset(pre, 0, sizeof(struct node));
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

static int tree_granularity(int l) {
  int x = l - lg_up(l) - 1;
  return (x < 0) ? 0 : x;
}

static bool nodes_share_n_bits(nodeid_t first, nodeid_t second, int bits) {
  nodeid_t mask = ((nodeid_t)__INT_MAX__) ^ (nodeid_t)(((int)1 << (CHORD_RING_BITS - bits)) - 1);
    if ((first & mask) == (second & mask)) {
      return true;
    }
    return false;
}

static nodeid_t get_share(struct node *node, struct node *successor) {
  assert(node);
  assert(successor);
  if (successor->id > node->id) {
    return successor->id - node->id;
  } else {
    return (CHORD_RING_SIZE - node->id) + successor->id;
  }
}

static nodeid_t find_splitnode(struct node *target) {

  struct node r, pre;
  find_successor(target, &r, mynode.id);
  struct node list[CHORD_RING_BITS];
  memset(list, 0, sizeof(list));
  for (int i = 0; i < CHORD_RING_BITS; i++) {
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
  int i, set = 0;
  for (i = 0; i < CHORD_RING_BITS; i++) {
    if (list[i].id != 0 && nodes_share_n_bits(r.id,list[i].id,tree_granularity(CHORD_RING_BITS))) {
      set++;
    }
  }
  nodeid_t share;
  if (set >= 1 << (CHORD_RING_BITS - tree_granularity(CHORD_RING_BITS))) {
    get_predecessor(&r, &pre);
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
      struct node *a, *b;
      if (i == 0) {
        a = &r;
        b = &list[0];
      } else {
        a = &list[i - 1];
        b = &list[i];
      }
      share = get_share(a, b);
      if (share > max_share) {
        max_share = share;
        max_id = i;
      }
    }
    return list[max_id].id-(max_share/2);
  }
}

static int
pop_successor(struct node* next)
{
  int i = 0;
  do {
    copy_node(&successorlist[0], next);
    memcpy(&successorlist[0],
           &successorlist[1],
           sizeof(successorlist) - sizeof(struct node));
    memset(&successorlist[SUCCESSORLIST_SIZE - 1], 0, sizeof(struct node));
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
    memset(&fingertable[i].node, 0, sizeof(struct node));
  }
  return CHORD_OK;
}

static int init_successorlist(void) {
  memset(successorlist, 0, sizeof(successorlist));
  return CHORD_OK;
}

static nodeid_t parent_function(nodeid_t id) {
  int k = 2;
  nodeid_t alpha = CHORD_RING_SIZE/2;
  int a = (id - alpha);
  if(a < 0 && a > -CHORD_RING_SIZE) {
    a = (((a%CHORD_RING_SIZE)+CHORD_RING_SIZE)%CHORD_RING_SIZE);
  } else {
    a = a % CHORD_RING_SIZE;
  }

  if (a >= 0 && a <= CHORD_RING_SIZE/2) {
    return (alpha + (a/k)) % CHORD_RING_SIZE;
  } else if (a > CHORD_RING_SIZE / 2 && a <= CHORD_RING_SIZE) {
    return (alpha - ((CHORD_RING_SIZE - a) / k)) % CHORD_RING_SIZE;
  } else {
    assert(true);
    return CHORD_ERR;
  }
}

static int
stabilize(struct node* node)
{
  struct node pre;
  int ret = CHORD_OK;
  if (!node_is_null(node->additional->successor)) {
    memset(&pre, 0, sizeof(pre));
    ret = get_predecessor(node->additional->successor, &pre);
    DEBUG(INFO,
          "got pre %d\n",
          (int)pre.id);
    if(pre.id == mynode.id && memcmp(&pre.addr,&mynode.addr,sizeof(pre.addr)) != 0) {
      set_nodeid(find_splitnode(node));
      find_successor(node, mynode.additional->successor, mynode.id);
      return CHORD_ERR;
    }
    if (ret != CHORD_ERR) {
      if (!node_is_null(&pre)) {
        if (node->id != pre.id && in_interval(node, node->additional->successor, pre.id)) {
          DEBUG(INFO,
                "looks like me->suc->pre is new: %d old: %d me: %d\n",
                pre.id,
                mynode.additional->successor->id,
                mynode.id);
          if (pre.id != mynode.additional->successor->id) {
            copy_node(&pre, &fingertable[0].node);
            update_successorlist(mynode.additional->successor);
            DEBUG(INFO, "Update successor to %d\n", mynode.additional->successor->id);
          }
        } else {
          DEBUG(DEBUG, "looks like me->suc->pre stays the same\n");
        }
      } else {
        memcpy(node->additional->predecessor, node->additional->successor, sizeof(struct node));
      }
      if (!node_is_null(mynode.additional->successor)) {
        notify(mynode.additional->successor);
      }
    } else {
      DEBUG(ERROR, "Could not reach successor\n");
    }
  }
  return ret;
}

static int
is_finger(struct node* n, struct fingertable_entry* entry)
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
fix_fingers(struct node* node)
{
  if (!node->additional->successor) {
    return;
  }

  // TODO: Not really sure if we want to ommit our successor.
  nodeid_t i = 0;
  do {
    i = rand() % CHORD_RING_BITS;
  } while (i == 0);
  struct fingertable_entry* f = &fingertable[i];

  DEBUG(INFO, "Fix finger %d\n", i);
  if (node->additional->successor && !node_is_null(node->additional->successor) &&
      (node->id != node->additional->successor->id)) {
    DEBUG(DEBUG,
          "Fix fingers find successor for %d ask: %d\n",
          f->start,
          node->additional->successor->id);

    nodeid_t id = ((f->start + f->interval) % CHORD_RING_SIZE);
    find_successor(node, &f->node, id);

    struct node* save = &f->node;
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
ping_node(struct node* node)
{
  if (node_is_null(node)) {
    return false;
  }
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshal_msg(MSG_TYPE_PING,
               node->id,
               sizeof(nodeid_t),
               (unsigned char*)(&(mynode.id)),
               msg);
  nodeid_t retid = 0;
  chord_msg_t type =
    chord_send_block_and_wait(node,
                              msg,
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
check_predecessor(struct node* node)
{
  DEBUG(INFO, "check pre %d\n", node->additional->predecessor->id);
  return ping_node(node->additional->predecessor);
}

static bool
check_successor(struct node* node)
{
  DEBUG(INFO, "check suc %d\n", node->additional->successor->id);
  return ping_node(node->additional->successor);
}

/*
static int
send_exit(struct node* node, struct node* update)
{
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshal_msg(
    MSG_TYPE_EXIT, node->id, sizeof(struct node), (unsigned char*)update, msg);

  while (true) {
    chord_msg_t type =
      chord_send_block_and_wait(node,
                                msg,
                                CHORD_HEADER_SIZE + sizeof(struct node),
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
node_exit(struct node* node)
{
  if (node->additional->successor && !node_is_null(node->additional->successor)) {
    struct node* update;
    if (node->additional->predecessor && !node_is_null(node->additional->predecessor)) {
      update = node->additional->predecessor;
    } else {
      update = &null_node;
    }
    DEBUG(INFO,
          "send exit to successor %d. Update node is %d\n",
          node->additional->successor->id,
          update->id);
    send_exit(node->additional->successor, update);
  }
  if (node->additional->predecessor && !node_is_null(node->additional->predecessor)) {
    struct node* update;
    if (node->additional->successor && !node_is_null(node->additional->successor)) {
      update = node->additional->successor;
    } else {
      update = &null_node;
    }
    DEBUG(INFO,
          "send exit to predeccessor %d. Update node is %d\n",
          node->additional->predecessor->id,
          update->id);

    send_exit(node->additional->predecessor, update);
  }
  return CHORD_OK;
}*/


static bool in_sync(void) {
  struct node *mynode = get_own_node();
  if (!node_is_null(mynode->additional->successor) && !node_is_null(mynode->additional->predecessor)) {
    return true;
  }
  return false;
}

static bool is_root(struct node *n, struct node *pre) {
  return in_interval(pre,n,(CHORD_RING_SIZE/2)-1);
}

static nodeid_t get_parent(struct child *c) {
  c->parent = mynode.id;
  c->i = 0;
  do {
    nodeid_t tmp = c->parent;
    c->parent = parent_function(c->parent);
    DEBUG(DEBUG,"parent function for %d is %d\n", tmp, c->parent);
    if(tmp != c->parent) {
      c->i++;
    }
  } while (in_interval(mynode.additional->predecessor,&mynode,c->parent-1));
  return CHORD_OK;
}

static int register_child(struct child *c){
  assert(c);
  struct child new;
  get_parent(&new);
  if(false && new.parent == c->parent) {
    return CHORD_OK;
  } else {
    c->parent = new.parent;
    c->i      = new.i;
  }
  chord_msg_t type = MSG_TYPE_CHORD_ERR;
  struct node* mynode = get_own_node();
  do {
    find_successor(mynode->additional->predecessor, &c->parent_suc, c->parent - 1);
  } while (c->parent_suc.id == mynode->id);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct child)];
  unsigned char ret[sizeof(struct node) + sizeof(struct aggregate)];
  do {
  DEBUG(INFO,
        "Register Child P^%d(%d) = %d on %d\n",
        c->i,
        get_own_node()->id,
        c->parent,
        c->parent_suc.id);
  marshal_msg(MSG_TYPE_REGISTER_CHILD,
               c->parent_suc.id,
               sizeof(struct child),
               (unsigned char*)c,
               msg);
  type = chord_send_block_and_wait(&c->parent_suc,
                                     msg,
                                     CHORD_HEADER_SIZE + sizeof(struct node) + sizeof(struct aggregate),
                                     MSG_TYPE_REGISTER_CHILD_OK,
                                     (unsigned char*)&ret,
                                     sizeof(ret),
                                     NULL);
  memcpy(&c->parent_suc, &ret, sizeof(struct node));
  memcpy(get_stats(), ret + sizeof(struct node), sizeof(struct aggregate));
  } while (type == MSG_TYPE_REGISTER_CHILD_REDIRECT);
  if (type == MSG_TYPE_REGISTER_CHILD_OK) {
    return CHORD_OK;
  } else {
    c->parent = 0;
    DEBUG(DEBUG, "get msg type %s\n", msg_to_string(type));
    return type;
  }
  return CHORD_OK;
}

static int refresh_parent(struct child *c) {
//  assert(c->parent_suc.id != get_own_node()->id);

  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct child)];
  marshal_msg(MSG_TYPE_REFRESH_CHILD,
               c->parent_suc.id,
               sizeof(struct child),
               (unsigned char*)c,
               msg);
  unsigned char ret[sizeof(struct node) + sizeof(struct aggregate)];
  chord_msg_t type = chord_send_block_and_wait(&c->parent_suc,
                              msg,
                              CHORD_HEADER_SIZE + sizeof(struct child),
                              MSG_TYPE_REFRESH_CHILD_OK,
                              (unsigned char*)&ret,
                              sizeof(ret),
                              NULL);
    memcpy(&c->parent_suc, &ret, sizeof(struct node));
    memcpy(get_stats(), (ret)+sizeof(struct node), sizeof(struct aggregate));
  if(type == MSG_TYPE_REFRESH_CHILD_REDIRECT) {
    register_child(c);
  } else if(type == MSG_TYPE_CHORD_ERR) {
    return CHORD_ERR;
  }
  return CHORD_ERR;
}
#ifdef DEBUG_ENABLE
static int get_nodes(void) {
  return get_stats()->nodes;
}

static int get_used(void) {
  return get_stats()->used;
}

static int get_size(void) {
  return get_stats()->available;
}
#endif

static int aggregate(struct aggregate *aggregation) {
  int nodes = 0, available = 0, used = 0;
  struct childs* childs = get_childs();
  time_t systime = time(NULL);
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if (childs->child[i].child != 0 && (systime-(childs->child[i].t)) < 3) {
      int n = childs->child[i].aggregation.nodes,
          a = childs->child[i].aggregation.available,
          u = childs->child[i].aggregation.used;
      (n > 0) ? nodes += n : nodes++;
      available += a;
      used += u;
    }
  }
  aggregation->nodes = ++nodes;
  aggregation->available = available + get_own_node()->size;
  aggregation->used = used + get_own_node()->used;
  return CHORD_OK;
}

/* Public functions */
int
copy_node(struct node* node, struct node* copy)
{
  memcpy(copy, node, sizeof(struct node));
  assert(copy->id == node->id);
  assert(memcmp(&node->addr,&copy->addr,sizeof(node->addr)) == 0);
  return CHORD_OK;
}

bool
in_interval_id(nodeid_t start, nodeid_t end, nodeid_t test)
{
  return (mod((test - start), CHORD_RING_SIZE) <
          mod((end - start), CHORD_RING_SIZE));
}

bool
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

int
get_mod_of_hash(unsigned char* hash, int modulo)
{
  int remainder = 0;
  for (int i = 0; i < HASH_DIGEST_SIZE; ++i)
    remainder = (remainder * 10 + hash[i]) % modulo;
  return remainder;
}

int
add_node(struct node* node)
{
  if (node) {
    if (CHORD_CHANGE_ID) {
      set_nodeid(find_splitnode(node));
    }

    for (int i = 1; i <= 3 && (join(&mynode, node) == CHORD_ERR); i++) {
      DEBUG(ERROR,
            "Unable to join retry in %d seconds(%d/3)\n",
            CHORD_PERIODIC_SLEEP,
            i);
      sleep(CHORD_PERIODIC_SLEEP);
    }
  } else {
    if (CHORD_CHANGE_ID) {
      set_nodeid(CHORD_RING_SIZE-1);
    }
    copy_node(&mynode, mynode.additional->successor);
    DEBUG(INFO, "Create new chord ring %d\n", mynode.additional->successor->id);
    for (int i = 0; i < FINGERTABLE_SIZE; i++) {
      if (i > 0) {
        copy_node(mynode.additional->successor, &fingertable[i].node);
      }
    }
    memset(successorlist, 0, sizeof(successorlist));
  }

  return CHORD_OK;
}

int
remove_dead_node(nodeid_t id)
{
  DEBUG(INFO, "Remove dead node %d\n", id);
  for (int i = 1; i < FINGERTABLE_SIZE; i++) {
    if (fingertable[i].node.id == id) {
      memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
    }
  }
  for (int i = 0; i < SUCCESSORLIST_SIZE; i++) {
    if (successorlist[i].id == id) {
      memset(&successorlist[i], 0, sizeof(successorlist[i]));
    }
  }
  return CHORD_OK;
}

int
init_chord(const char* addr)
{
  memset(&mynode, 0, sizeof(mynode));
  memset(&my_additional, 0, sizeof(my_additional));
  memset(&predecessor, 0, sizeof(predecessor));
  memset(&childs, 0, sizeof(struct child));
  start = time(NULL);
  if (addr_to_node(&mynode, addr) == CHORD_ERR) {
    DEBUG(ERROR, "Error while translating address %s to binary\n", addr);
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
  mynode.additional = &my_additional;

  init_fingertable();
  init_successorlist();

  struct aggregate* a = get_stats();
  mynode.size = 1024;
  mynode.used = 0;
  a->used = 0;
  a->nodes = 0;

  struct hooks *h = get_hooks();
  h->periodic_hook = NULL;

  return CHORD_OK;
}

bool
node_is_null(struct node* node)
{
  if (!node) {
    return false;
  }
  if (node->id == 0) {
    return true;
  }
  return false;
}

int
chord_send_block_and_wait(struct node* target,
                          unsigned char* msg,
                          size_t size,
                          chord_msg_t wait,
                          unsigned char* buf,
                          size_t bufsize,
                          size_t *ret_size)
{
  unsigned char read_buf[MAX_MSG_SIZE];
  nodeid_t src_id, dst_id;
  size_t msg_size;
  unsigned char* msg_content;
  struct socket_wrapper sock;

  int s = sock_wrapper_open(&sock,get_own_node(),target,CHORD_PORT+1,CHORD_PORT);
  if (s == -1) {
    DEBUG(ERROR, "socket: %s\n", strerror(errno));
    return MSG_TYPE_CHORD_ERR;
  }
  DEBUG(DEBUG, "New socket %d\n", s);
  DEBUG(DEBUG, "chord_send_block_and_wait new sock: %d\n", s);
  int ret = 0;
  while (ret < (int)size) {
    int tmp = sock_wrapper_send(&sock, msg+ret, size-ret);
    if (tmp < 0) {
      DEBUG(ERROR, "write: %s", strerror(errno));
      sock_wrapper_close(&sock);
      return MSG_TYPE_CHORD_ERR;
    }
    ret += tmp;
  }
  if (wait == MSG_TYPE_NO_WAIT) {
    sock_wrapper_close(&sock);
    return MSG_TYPE_NO_WAIT;
  }

  chord_msg_t type = 0;

  DEBUG(DEBUG, "Wait for answer\n");
  ret = sock_wrapper_recv(&sock,read_buf,MAX_MSG_SIZE,TIMEOUT);
  DEBUG(INFO, "Got %d\n",ret);
  if (ret < (int)CHORD_HEADER_SIZE) {
    DEBUG(ERROR,
          "Error in recv: %s (received) %d < (CHORD_HEADER_SIZE) %d\n",
          strerror(errno),
          ret,
          CHORD_HEADER_SIZE);
    sock_wrapper_close(&sock);
    return MSG_TYPE_CHORD_ERR;
  }

  demarshal_msg(read_buf, &type, &src_id, &dst_id, &msg_size, &msg_content);
  DEBUG(DEBUG,
        "Found Msg type %s (%d) from %d to %d size %d. Wait for: %s (%d)\n",
        msg_to_string(type),
        type,
        src_id,
        dst_id,
        (int)msg_size,
        msg_to_string(wait),
        wait);
  if(size > MAX_MSG_SIZE) {
    //HOTFIX https://github.com/RIOT-OS/RIOT/issues/10389
    return CHORD_OK;
  }
  assert((int)type >= 0);
  assert((int)src_id > 0);
  assert((int)dst_id > 0);
  assert((int)msg_size >= 0);
  assert((int)msg_size < MAX_MSG_SIZE);
  if (msg_size > bufsize) {
    msg_size = bufsize;
  }
  memcpy(buf, msg_content, msg_size);
  if(ret_size)
    *ret_size = msg_size;
  sock_wrapper_close(&sock);
  return type;
}

int
get_successorlist_id(struct node *target, nodeid_t *id) {
  assert(target);
  unsigned char msg[CHORD_HEADER_SIZE];
  marshal_msg(
      MSG_TYPE_GET_SUCCESSORLIST_ID, target->id, 0, NULL, msg);
    chord_msg_t type =
      chord_send_block_and_wait(target,
                                msg,
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

static int chord_find_successor(struct node *target, struct node *ret, nodeid_t id) {
  struct node *final = NULL, *tmp = target;
  int steps = 1;
  chord_msg_t query_type = MSG_TYPE_FIND_SUCCESSOR;
  DEBUG(INFO, "Start find successor ask: %d for %d\n", target->id, id);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  while (final == NULL) {
    memset(msg, 0, sizeof(msg)); //TODO Remove
    marshal_msg(
      query_type, tmp->id, sizeof(nodeid_t), (unsigned char*)&id, msg);
    chord_msg_t type =
      chord_send_block_and_wait(tmp,
                                msg,
                                CHORD_HEADER_SIZE + sizeof(nodeid_t),
                                MSG_TYPE_FIND_SUCCESSOR_RESP,
                                (unsigned char*)ret,
                                sizeof(struct node),
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
    memset(ret, 0, sizeof(struct node));
    return CHORD_ERR;
  }
  DEBUG(INFO, "Found successor for %d on %d steps: %d\n", id, steps, ret->id);
  return CHORD_OK;
}

int
find_successor(struct node* target, struct node* ret, nodeid_t id)
{
  assert(id <= CHORD_RING_SIZE);
  struct node* self = get_own_node();
  if (!node_is_null(self->additional->predecessor) &&
      in_interval(self->additional->predecessor, self, id)) {
    copy_node(get_own_node(),ret);
    return CHORD_OK;
  } else {
    return chord_find_successor(target, ret, id);
  }
}

int
notify(struct node* target)
{
  if (!target) {
    DEBUG(ERROR, "notify target is NULL\n");
    return CHORD_ERR;
  }
  DEBUG(INFO, "Notify successor %d\n", target->id);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshal_msg(MSG_TYPE_NOTIFY,
               target->id,
               sizeof(struct node),
               (unsigned char*)(&mynode),
               msg);
  chord_msg_t type =
    chord_send_block_and_wait(target,
                              msg,
                              CHORD_HEADER_SIZE + sizeof(struct node),
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

int
join(struct node* src, struct node* target)
{
  memset(src->additional->predecessor, 0, sizeof(struct node));
  if (find_successor(target, src->additional->successor, src->id) == CHORD_ERR) {
    return CHORD_ERR;
  }
  if (node_is_null(src->additional->successor)) {
    DEBUG(ERROR, "Unable to find successor exit\n");
    return CHORD_ERR;
  }
  DEBUG(INFO, "Update successorlist\n");
  update_successorlist(src->additional->successor);
  return CHORD_OK;
}

int
create_node(char* address, struct node* node)
{
  if (!address) {
    DEBUG(FATAL, "Error address is NULL in create node\n");
    return CHORD_ERR;
  }
  memset(&node->addr, 0, sizeof(node->addr));

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

void*
thread_wait_for_msg(void* n)
{
  int iteration = 0;
  struct node* node = (struct node*)n;
  struct socket_wrapper s;
  if(sock_wrapper_open(&s,get_own_node(),NULL,CHORD_PORT,0) != 0) {
    DEBUG(ERROR,"Error while open new port\n");
    return NULL;
  }
  while (1) {
    iteration++;
    DEBUG(INFO, "wait for message run %d\n", iteration);
    if (wait_for_message(node, &s) == CHORD_ERR) {
      DEBUG(ERROR, "error in wait_for_message\n");
    }
  }
  return NULL;
}


void*
thread_periodic(void* n)
{
  int i = 0;
  struct node partner;
  copy_node((struct node*)n, &partner);
  struct node* node = &mynode;
  struct child c;
  memset(&c, 0, sizeof(c));
  while (1) {
    struct hooks *h = get_hooks();
    atm = time(NULL);
    #ifdef DEBUG_ENABLE
    time_t runtime = atm - start;
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
    assert(!node_is_null(mynode.additional->successor));
    assert(node->id > 0);
    if (node_is_null(node->additional->successor)) {
      // join(node, &partner);
    }
    i++;
    assert(node->additional->successor);
    assert(node->additional->predecessor);

    DEBUG(INFO, "Start stabilization Procedure\n");
    nodeid_t old = mynode.id;
    if (stabilize(node) == CHORD_OK) {
      if (!node_is_null(node->additional->successor)) {
        DEBUG(INFO, "Update successorlist\n");
        update_successorlist(node->additional->successor);
      }
    } else {
      if(old != mynode.id) {
        continue;
      }
      DEBUG(ERROR, "Error in stabilization Procedure: %d\n");
    }

    if (!node_is_null(node->additional->predecessor) && !check_predecessor(node)) {
      DEBUG(
        ERROR, "ERROR PRE %d Do not respond to ping\n", node->additional->predecessor->id);
      remove_dead_node(node->additional->predecessor->id);
      memset(node->additional->predecessor, 0, sizeof(struct node));
    }

    if (!node_is_null(node->additional->successor) && !check_successor(node)) {
      DEBUG(
        ERROR, "Error: suc %d do not respond to ping\n", node->additional->successor->id);
      remove_dead_node(node->additional->successor->id);
      pop_successor(node->additional->successor);
      DEBUG(INFO, "Update successor to %d\n", node->additional->successor->id);
    }


    DEBUG(INFO, "Aggregate Stats\n");
    aggregate(&c.aggregation);
    if (!is_root(&mynode, mynode.additional->predecessor)) {
      if (!node_is_null(node->additional->predecessor) && !node_is_null(node->additional->successor)) {
        register_child(&c);
      }
      if(!node_is_null(&c.parent_suc)) {
        if(refresh_parent(&c) == CHORD_ERR) {
          memset(&c.parent_suc, 0, sizeof(struct node));
        }
      }
    } else {
      memcpy(get_stats(), &c.aggregation, sizeof(struct aggregate));
      DEBUG(INFO,
            "root got %d nodes %d/%d used\n",
            get_nodes(),
            get_used(),
            get_size());
    }

    if (in_sync() && h->periodic_hook) {
      DEBUG(INFO, "Call periodic Hook\n");
      h->periodic_hook(h->periodic_data);
    }

    fix_fingers(node);

#ifdef DEBUG_ENABLE
    debug_print_node(node, false);
#endif
    sleep(CHORD_PERIODIC_SLEEP);
  }
  return NULL;
}
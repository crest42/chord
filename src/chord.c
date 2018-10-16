
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

static bool
in_interval_id(int start, int end, int test)
{
  return (mod((test - start), CHORD_RING_SIZE) <
          mod((end - start), CHORD_RING_SIZE));
}

int
copy_node(struct node* node, struct node* copy)
{
  memcpy(copy, node, sizeof(struct node));
  assert(copy->addr.sin6_family == node->addr.sin6_family);
  assert(copy->id == node->id);
  return CHORD_OK;
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

struct key**
get_first_key(void)
{
  return &first_key;
}

static int
update_successorlist(struct node* src)
{
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshall_msg(MSG_TYPE_COPY_SUCCESSORLIST,
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
                              (sizeof(successorlist) - sizeof(struct node)));
  if (type == MSG_TYPE_COPY_SUCCESSORLIST_RESP) {
    memcpy(successorlist, src, sizeof(struct node));
    return CHORD_OK;
  } else {
    DEBUG(DEBUG, "get msg type %s\n", msg_to_string(type));
    return CHORD_ERR;
  }
  return CHORD_OK;
}

static int tree_granularity() {
  return 0;
}

/*static int dec_to_str(int dec){
  int k;
  for (int c = 16; c >= 0; c--) {
    k = dec >> c;
    if (k & 1)
      printf("1");
    else
      printf("0");
  }
      printf("\n");

  return CHORD_OK;
}*/

static int find_splitnode(struct node *target, struct node *ret) {
  find_successor(target, ret, mynode.id);
  struct node list[CHORD_RING_BITS];
  memset(list, 0, sizeof(list));
  for (int i = 0; i < CHORD_RING_BITS; i++) {
    if(i == 0) {
      find_successor(target, &list[i], target->id);
    } else {
      find_successor(target, &list[i], list[i-1].id);
    }
  }
  int i, set = 0;
  nodeid_t myid = mynode.id | (1 << (CHORD_RING_BITS - tree_granularity()));
  for (i = 0; i < CHORD_RING_BITS; i++) {
    nodeid_t id =
      list[i].id | (1 << (CHORD_RING_BITS - tree_granularity()));
    nodeid_t mask =
      ((nodeid_t)__INT_MAX__) ^
      (((nodeid_t)1 << (CHORD_RING_BITS - tree_granularity())) - 1);
    if ((myid & mask) == (id & mask)) {
      set++;
    }
  }
  if (i >= (CHORD_RING_BITS - tree_granularity())) {
    return CHORD_OK;
  } else {
    nodeid_t max = 0;
    int max_id = 0;
    for (; i < SUCCESSORLIST_SIZE-1; i++) {
      if(i<SUCCESSORLIST_SIZE-1 && successorlist[i+1].id-successorlist[i].id > max) {
        max = successorlist[i + 1].id - successorlist[i].id;
        max_id = i;
      }
    }
    memcpy(ret,&successorlist[max_id],sizeof(struct node));
  }
  return CHORD_OK;
}

int
add_node(struct node* node)
{
  if (node) {
    if (CHORD_CHANGE_ID) {
      struct node n;
      struct node suc;
      find_splitnode(node, &n);
      find_successor(node, &suc, n.id);
      if(suc.id != n.id) {
        if(suc.id > n.id) {
          mynode.id = (n.id+((suc.id - n.id) / 2))%CHORD_RING_SIZE;
        } else {
          mynode.id = (n.id+(((CHORD_RING_SIZE - n.id) + suc.id) / 2))%CHORD_RING_SIZE;
        }
      } else {
        mynode.id = n.id / 2;
      }
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
      mynode.id = CHORD_RING_SIZE;
    }
    copy_node(&mynode, mynode.successor);
    DEBUG(INFO, "Create new chord ring %d\n", mynode.successor->id);
    for (int i = 0; i < FINGERTABLE_SIZE; i++) {
      if (i > 0) {
        copy_node(mynode.successor, &fingertable[i].node);
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
    memset(&fingertable[i].node, 0, sizeof(struct node));
  }
  return CHORD_OK;
}

static int init_successorlist(void) {
  memset(successorlist, 0, sizeof(successorlist));
  return CHORD_OK;
}

int
init_chord(const char* addr)
{
  memset(&mynode, 0, sizeof(mynode));
  memset(&predecessor, 0, sizeof(predecessor));
  first_key = NULL;
  last_key = NULL;

  if (bind_socket(&mynode,addr) == CHORD_ERR) {
    return CHORD_ERR;
  }

  unsigned char hash_id[HASH_DIGEST_SIZE];
  hash(hash_id,
       (unsigned char*)&(mynode.addr.sin6_addr),
       sizeof(mynode.addr.sin6_addr),
       HASH_DIGEST_SIZE);
  mynode.id = get_mod_of_hash(hash_id, CHORD_RING_SIZE);

  mynode.predecessor = &predecessor;
  mynode.successor = &fingertable[0].node;

  init_fingertable();
  init_successorlist();

  return 0;
}

bool
node_is_null(struct node* node)
{
  if (!node) {
    return false;
  }
  if (node->id == 0 && !node->successor && !node->predecessor) {
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
                          size_t bufsize)
{
  assert(target->addr.sin6_family == AF_INET6);

  unsigned char read_buf[MAX_MSG_SIZE];
  nodeid_t src_id, dst_id;
  size_t msg_size;
  unsigned char* msg_content;

  int s = socket(AF_INET6, SOCK_DGRAM, 0);
  if (s == -1) {
    DEBUG(ERROR, "socket: %s\n", strerror(errno));
    return MSG_TYPE_CHORD_ERR;
  }
  DEBUG(DEBUG, "New socket %d\n", s);

  if (setsockopt(
        s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tout, sizeof(struct timeval)) < 0) {
    DEBUG(ERROR, "set socket timeout: %s\n", strerror(errno));
  }
  DEBUG(DEBUG, "chord_send_block_and_wait new sock: %d\n", s);

  struct sockaddr_in6 src_addr;
  assert(target->addr.sin6_port == htons(CHORD_PORT));
  memcpy(&src_addr, &mynode.addr, sizeof(struct sockaddr_in6));
  src_addr.sin6_port = htons(CHORD_PORT + 1);
  DEBUG(INFO, "bind to %d\n", ntohs(src_addr.sin6_port));
  if (bind(s, (struct sockaddr*)&src_addr, sizeof(struct sockaddr_in6)) == -1) {
    DEBUG(ERROR, "bind: %s\n", strerror(errno));
    close(s);
    return MSG_TYPE_CHORD_ERR;
  }
  DEBUG(DEBUG,
        "connect to port %d (id %d)\n",
        ntohs(target->addr.sin6_port),
        target->id);
  if (connect(s,
              (struct sockaddr*)&target->addr,
              sizeof(struct sockaddr_in6)) == -1) {
    close(s);
    DEBUG(ERROR, "connect %d: %s", s, strerror(errno));
    return MSG_TYPE_CHORD_ERR;
  }
  int ret = 0;
  while (ret < (int)size) {
    int tmp = sendto(s,
                     msg + ret,
                     size - ret,
                     0,
                     (struct sockaddr*)&target->addr,
                     sizeof(struct sockaddr_in6));
    if (tmp < 0) {
      DEBUG(ERROR, "write: %s", strerror(errno));
      close(s);
      return MSG_TYPE_CHORD_ERR;
    }
    ret += tmp;
  }
  if (wait == MSG_TYPE_NO_WAIT) {
    close(s);
    return MSG_TYPE_NO_WAIT;
  }

  chord_msg_t type = 0;
  DEBUG(DEBUG, "Wait for answer\n");
  ret = recv(s, read_buf, MAX_MSG_SIZE, 0);

  if (ret < (int)CHORD_HEADER_SIZE) {
    DEBUG(ERROR,
          "Error in recv %s (received) %d < (CHORD_HEADER_SIZE) %d\n",
          strerror(errno),
          ret,
          CHORD_HEADER_SIZE);
    close(s);
    return MSG_TYPE_CHORD_ERR;
  }

  demarshall_msg(read_buf, &type, &src_id, &dst_id, &msg_size, &msg_content);
  DEBUG(DEBUG,
        "Found Msg type %s (%d) from %d to %d size %d. Wait for: %s (%d)\n",
        msg_to_string(type),
        type,
        src_id,
        dst_id,
        (int)msg_size,
        msg_to_string(wait),
        wait);

  if (msg_size > bufsize) {
    msg_size = bufsize;
  }
  memcpy(buf, msg_content, msg_size);
  close(s);
  return type;
}

static int
get_predecessor(struct node* src, struct node* pre)
{
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshall_msg(MSG_TYPE_GET_PREDECESSOR,
               src->id,
               sizeof(nodeid_t),
               (unsigned char*)(&(mynode.id)),
               msg);
  chord_msg_t type =
    chord_send_block_and_wait(src,
                              msg,
                              CHORD_HEADER_SIZE + sizeof(nodeid_t),
                              MSG_TYPE_GET_PREDECESSOR_RESP,
                              (unsigned char*)pre,
                              sizeof(struct node));
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

int
find_successor(struct node* target, struct node* ret, nodeid_t id)
{
  assert(id <= CHORD_RING_SIZE);
  struct node *final = NULL, *tmp = target;
  int steps = 1;
  chord_msg_t query_type = MSG_TYPE_FIND_SUCCESSOR;

  DEBUG(INFO, "Start find successor ask: %d for %d\n", target->id, id);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  while (final == NULL) {
    memset(msg, 0, sizeof(msg));
    marshall_msg(
      query_type, tmp->id, sizeof(nodeid_t), (unsigned char*)&id, msg);
    chord_msg_t type =
      chord_send_block_and_wait(tmp,
                                msg,
                                CHORD_HEADER_SIZE + sizeof(nodeid_t),
                                MSG_TYPE_FIND_SUCCESSOR_RESP,
                                (unsigned char*)ret,
                                sizeof(struct node));
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
notify(struct node* target)
{
  if (!target) {
    DEBUG(ERROR, "notify target is NULL\n");
    return CHORD_ERR;
  }
  DEBUG(INFO, "Notify successor %d\n", target->id);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshall_msg(MSG_TYPE_NOTIFY,
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
                              0);
  if (type == MSG_TYPE_CHORD_ERR) {
    DEBUG(ERROR, "Error in notify returned msg type MSG_TYPE_CHORD_ERR\n");
    return CHORD_ERR;
  }
  return CHORD_OK;
}

int
join(struct node* src, struct node* target)
{
  memset(src->predecessor, 0, sizeof(struct node));
  if (find_successor(target, src->successor, src->id) == CHORD_ERR) {
    return CHORD_ERR;
  }
  if (node_is_null(src->successor)) {
    DEBUG(ERROR, "Unable to find successor exit\n");
    return CHORD_ERR;
  }
  DEBUG(INFO, "Update successorlist\n");
  update_successorlist(src->successor);
  return CHORD_OK;
}

static int
stabilize(struct node* node)
{
  struct node pre;
  int ret = CHORD_OK;
  if (!node_is_null(node->successor)) {
    memset(&pre, 0, sizeof(pre));
    ret = get_predecessor(node->successor, &pre);
    DEBUG(INFO,
          "got pre %p with id %d ret: %d %d\n",
          (void*)&pre,
          (int)pre.id,
          ret,
          CHORD_ERR);
    if (ret != CHORD_ERR) {
      if (!node_is_null(&pre)) {
        if (node->id != pre.id && in_interval(node, node->successor, pre.id)) {
          DEBUG(INFO,
                "looks like me->suc->pre is new: %d old: %d me: %d\n",
                pre.id,
                mynode.successor->id,
                mynode.id);
          if (pre.id != mynode.successor->id) {
            copy_node(&pre, &fingertable[0].node);
            update_successorlist(mynode.successor);
            DEBUG(INFO, "Update successor to %d\n", mynode.successor->id);
          }
        } else {
          DEBUG(DEBUG, "looks like me->suc->pre stays the same\n");
        }
      } else {
        memcpy(node->predecessor, node->successor, sizeof(struct node));
      }
      if (!node_is_null(mynode.successor)) {
        notify(mynode.successor);
      }
    } else {
      DEBUG(ERROR, "Could not reach successor\n");
    }
  }
  return ret;
}

int
create_node(char* address, struct node* node)
{
  if (!address) {
    DEBUG(FATAL, "Error address is NULL in create node\n");
    return CHORD_ERR;
  }
  memset(&node->addr, 0, sizeof(node->addr));

  int c = inet_pton(AF_INET6, address, &(node->addr.sin6_addr));
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
       (unsigned char*)&node->addr.sin6_addr,
       sizeof(node->addr.sin6_addr),
       sizeof(hash_id));
  node->id = get_mod_of_hash(hash_id, CHORD_RING_SIZE);

  DEBUG(INFO, "create node with addr %s\n", address);

  node->addr.sin6_family = AF_INET6;
  node->addr.sin6_port = htons(CHORD_PORT);

  bind(
    node->socket, (struct sockaddr*)&mynode.addr, sizeof(struct sockaddr_in6));

  return CHORD_OK;
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
  if (!node->successor) {
    return;
  }

  // TODO: Not really sure if we want to ommit our successor.
  nodeid_t i = 0;
  do {
    i = rand() % CHORD_RING_BITS;
  } while (i == 0);
  struct fingertable_entry* f = &fingertable[i];

  DEBUG(INFO, "Fix finger %d\n", i);
  if (node->successor && !node_is_null(node->successor) &&
      (node->id != node->successor->id)) {
    DEBUG(INFO,
          "Fix fingers find successor for %d ask: %d\n",
          f->.start,
          node->successor->id);

    nodeid_t id = ((f->start + f->interval) % CHORD_RING_SIZE);
    find_successor(node, &f->node, id);

    struct node* save = &f->node;
    if (!node_is_null(save)) {
      while (i + 1 < FINGERTABLE_SIZE - 1 &&
             is_finger(&fingertable[i].node, &fingertable[i + 1])) {
        if (save->id != fingertable[i + 1].node.id) {
          DEBUG(INFO,
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
  marshall_msg(MSG_TYPE_PING,
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
                              sizeof(nodeid_t));
  if (type == MSG_TYPE_PONG && retid == node->id) {
    return true;
  } else {
    return false;
  }
}

static bool
check_predecessor(struct node* node)
{
  DEBUG(INFO, "check pre %d\n", node->predecessor->id);
  return ping_node(node->predecessor);
}

static bool
check_successor(struct node* node)
{
  DEBUG(INFO, "check suc %d\n", node->successor->id);
  return ping_node(node->successor);
}

void*
thread_wait_for_msg(void* n)
{
  int iteration = 0;
  struct node* node = (struct node*)n;
  while (1) {
    iteration++;
    DEBUG(INFO, "wait for message run %d\n", iteration);
    if (wait_for_message(node, NULL, 0) == CHORD_ERR) {
      DEBUG(ERROR, "error in wait_for_message\n");
    }
  }
  return NULL;
}
/*
static int
send_exit(struct node* node, struct node* update)
{
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshall_msg(
    MSG_TYPE_EXIT, node->id, sizeof(struct node), (unsigned char*)update, msg);

  while (true) {
    chord_msg_t type =
      chord_send_block_and_wait(node,
                                msg,
                                CHORD_HEADER_SIZE + sizeof(struct node),
                                MSG_TYPE_EXIT_ACK,
                                NULL,
                                0);
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
  if (node->successor && !node_is_null(node->successor)) {
    struct node* update;
    if (node->predecessor && !node_is_null(node->predecessor)) {
      update = node->predecessor;
    } else {
      update = &null_node;
    }
    DEBUG(INFO,
          "send exit to successor %d. Update node is %d\n",
          node->successor->id,
          update->id);
    send_exit(node->successor, update);
  }
  if (node->predecessor && !node_is_null(node->predecessor)) {
    struct node* update;
    if (node->successor && !node_is_null(node->successor)) {
      update = node->successor;
    } else {
      update = &null_node;
    }
    DEBUG(INFO,
          "send exit to predeccessor %d. Update node is %d\n",
          node->predecessor->id,
          update->id);

    send_exit(node->predecessor, update);
  }
  return CHORD_OK;
}*/

void*
thread_periodic(void* n)
{
  int i = 0;
  struct node partner;
  copy_node((struct node*)n, &partner);
  struct node* node = &mynode;

  while (1) {
    DEBUG(INFO, "%d: sockid: %d periodic run %d\n", node->id, node->socket, i);
    assert(!node_is_null(mynode.successor));
    assert(node->id > 0);
    if (node_is_null(node->successor)) {
      // join(node, &partner);
    }
    i++;
    assert(node->successor);
    assert(node->predecessor);

    DEBUG(INFO, "stabilze\n");
    if (stabilize(node) == CHORD_OK) {
      if (!node_is_null(node->successor)) {
        DEBUG(INFO, "Update successorlist\n");
        update_successorlist(node->successor);
      }
    }

    if (!node_is_null(node->predecessor) && !check_predecessor(node)) {
      DEBUG(
        ERROR, "ERROR PRE %d Do not respond to ping\n", node->predecessor->id);
      remove_dead_node(node->predecessor->id);
      memset(node->predecessor, 0, sizeof(struct node));
    }
    if (!node_is_null(node->successor) && !check_successor(node)) {
      DEBUG(
        ERROR, "Error: suc %d do not respond to ping\n", node->successor->id);
      remove_dead_node(node->successor->id);
      pop_successor(node->successor);
      DEBUG(INFO, "Update successor to %d\n", node->successor->id);
    }


    DEBUG(INFO, "Fix fingers\n");
    fix_fingers(node);
#ifdef DEBUG_ENABLE
    debug_print_node(node, false);
#endif
    sleep(CHORD_PERIODIC_SLEEP);
  }
  return NULL;
}
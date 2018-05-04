
/**
 * @file chord.c
 * @author Robin Lösch
 * @date 18 Apr 2018
 * @brief File implements the chord Protocol
 *
 * @see http://nms.csail.mit.edu/papers/chord.pdf
 * @see https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf
 */

#include "chord.h"
#include "chord_internal.h"
#include <assert.h>
#include <unistd.h>
int
get_mod_of_hash(unsigned char* hash, int modulo)
{
  int remainder = 0;
  for (int i = 0; i < HASH_DIGEST_SIZE; ++i)
    remainder = (remainder * 10 + hash[i]) % modulo;
  return remainder;
}

static nodeid_t
chord_abs(nodeid_t a, nodeid_t b)
{
  if (b < a) {
    return CHORD_RING_SIZE - a + b;
  } else {
    return b - a;
  }
}

static bool
is_own_id(nodeid_t id)
{
  for (int i = 0; i < CHORD_RING_BITS; i++) {
    if (pnodes[i] == id) {
      return true;
    }
  }
  return false;
}

static int
copy_node(struct node* node, struct node* copy)
{
  memcpy(copy, node, sizeof(struct node));
  assert(copy->addr.sin6_family == node->addr.sin6_family);
  assert(copy->id == node->id);
  return CHORD_OK;
}

static bool
is_pre(nodeid_t id)
{
  if (node_is_null(mynode.predecessor)) {
    return true;
  }
  if (in_interval(mynode.predecessor, &mynode, id)) {
    return true;
  }
  return false;
}

struct chord_callbacks*
get_callbacks(void)
{
  return &cc;
}

struct key**
get_first_key(void)
{
  return &first_key;
}

static int
get_min_addr_order(int start, int end, int* orda, int* ordb)
{
  if (start > end) {
    *orda = 0;
    *ordb = 0;
  } else if (start == end) {
    int down = __builtin_ctz(start);
    *orda = CHORD_RING_BITS - (down);
    *ordb = ((start >> (down)) - 1) / 2;
  } else {
    for (int a = 1; a < (1 << (CHORD_RING_BITS + 1)); a = a * 2) {
      for (int b = 1; b < a; b = b + 2) {
        int sum = CHORD_RING_SIZE * b / a;
        if (sum >= start && sum < end) {
          *orda = CHORD_RING_BITS - __builtin_ctz(sum);
          *ordb = (b - 1) / 2;
          return CHORD_OK;
        }
      }
    }
  }
  return CHORD_OK;
}

static int
get_active_node(struct node* src, nodeid_t* opt, struct node* save_node)
{
  int min_a = __INT_MAX__, min_b = __INT_MAX__, a = 0, b = 0;
  nodeid_t save = 0;
  struct node node;

  for (int i = 0; i < CHORD_RING_BITS; i++) {
    if (!(i > 0 && pnodes[i] > pnodes[i - 1] && pnodes[i] < save_node->id)) {
      if (find_successor(src, &node, pnodes[i]) == CHORD_ERR) {
        return CHORD_ERR;
      }
    }
    get_min_addr_order((int)pnodes[i] + 1, (int)node.id, &a, &b);
    if (a < min_a || (a == min_a && b < min_b) ||
        (a == min_a && b == min_b && pnodes[i] > save)) {
      min_a = a;
      min_b = b;
      save = pnodes[i];
      copy_node(&node, save_node);
    }
  }
  if (opt) {
    *opt = save;
  }
  return CHORD_OK;
}

int
add_node(struct node* node)
{
  if (node) {
    if (CHORD_CHANGE_ID) {
      nodeid_t id;
      node->id = CHORD_RING_SIZE;
      struct node save;
      get_active_node(node, &id, &save);
      mynode.id = id;
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
      mynode.id = pnodes[CHORD_RING_BITS - 1];
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
  } while ((is_own_id(successorlist[0].id) || node_is_null(next)) &&
           i < SUCCESSORLIST_SIZE);
  return CHORD_OK;
}

static int
bind_socket(struct node* node)
{
  node->socket = socket(AF_INET6, SOCK_DGRAM, 0);
  if (node->socket < 0) {
    DEBUG(ERROR, "Error while creating socket");
    return CHORD_ERR;
  }
  DEBUG(DEBUG, "new sock: %d\n", node->socket);

  int option = 1;
  setsockopt(node->socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

  node->addr.sin6_family = AF_INET6;
  node->addr.sin6_port = htons(CHORD_PORT);
  DEBUG(INFO, "bind %d %s\n", CHORD_PORT, strerror(errno));
  if ((bind(node->socket, (struct sockaddr*)&node->addr, sizeof(node->addr))) ==
      -1) {
    DEBUG(ERROR, "Error on bind");
    return CHORD_ERR;
  }
  return CHORD_OK;
}

static int
init_fingertable(void)
{
  nodeid_t start = 0;
  nodeid_t interval = 0;
  for (int i = 0; i < FINGERTABLE_SIZE; i++) {
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

static int
cmp(const void* a, const void* b)
{
  return (*(int*)a - *(int*)b);
}

int
init_chord(const char* node_addr)
{
  memset(&mynode, 0, sizeof(mynode));
  memset(&predecessor, 0, sizeof(predecessor));
  memset(successorlist, 0, sizeof(successorlist));
  int ret = inet_pton(AF_INET6, node_addr, &(mynode.addr.sin6_addr));
  if (ret != 1) {
    if (ret == -1) {
      DEBUG(ERROR, "Error in inet_pton");
    } else if (ret == 0) {
      DEBUG(ERROR, "Addr is not a valid IPv6 address\n");
    } else {
      DEBUG(ERROR, "Unknown error in inet_pton\n");
    }
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
  srand(mynode.id);
  first_key = NULL;
  last_key = NULL;
  if (bind_socket(&mynode) == CHORD_ERR) {
    return CHORD_ERR;
  }
  pnodes[0] = mynode.id;
  for (int i = 1; i < CHORD_RING_BITS; i++) {
    hash(hash_id, hash_id, HASH_DIGEST_SIZE, HASH_DIGEST_SIZE);
    pnodes[i] = get_mod_of_hash(hash_id, CHORD_RING_SIZE);
  }
  qsort(pnodes, CHORD_RING_BITS, sizeof(nodeid_t), cmp);
  DEBUG(INFO, "Possible node id's: ");
#ifdef DEBUG_ENABLE
  for (int i = 0; i < CHORD_RING_BITS; i++) {
    printf("%d, ", pnodes[i]);
  }
  printf("\n");
#endif
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
chord_send_nonblock_sock(int sock,
                         unsigned char* msg,
                         size_t size,
                         struct sockaddr* addr,
                         socklen_t addr_len)
{
  return sendto(sock, msg, size, 0, addr, addr_len);
}

int
marshall_msg(chord_msg_t msg_type,
             nodeid_t dst_id,
             size_t size,
             unsigned char* content,
             unsigned char* msg)
{
  assert(msg_type > 0);
  assert(dst_id > 0);
  assert(mynode.id > 0);

  DEBUG(DEBUG,
        "craft msg %s with size %d from %d to dst: %d\n",
        msg_to_string(msg_type),
        (int)size,
        mynode.id,
        dst_id);
  memcpy(&msg[CHORD_MSG_COMMAND_SLOT], &msg_type, CHORD_MSG_COMMAND_SIZE);
  memcpy(&msg[CHORD_MSG_SRC_ID_SLOT], &(mynode.id), CHORD_MSG_SRC_ID_SIZE);
  memcpy(&msg[CHORD_MSG_DST_ID_SLOT], &dst_id, CHORD_MSG_DST_ID_SIZE);
  memcpy(&msg[CHORD_MSG_LENGTH_SLOT], &size, CHORD_MSG_LENGTH_SIZE);
  if (content != NULL && size > 0) {
    memcpy(&msg[CHORD_HEADER_SIZE], content, size);
  }
  return CHORD_OK;
}

int
demarshall_msg(unsigned char* buf,
               chord_msg_t* type,
               nodeid_t* src_id,
               nodeid_t* dst_id,
               size_t* size,
               unsigned char** content)
{
  assert(buf);
  if (type) {
    memcpy(type, &buf[CHORD_MSG_COMMAND_SLOT], CHORD_MSG_COMMAND_SIZE);
  }
  if (src_id) {
    memcpy(src_id, &buf[CHORD_MSG_SRC_ID_SLOT], CHORD_MSG_SRC_ID_SIZE);
  }
  if (dst_id) {
    memcpy(dst_id, &buf[CHORD_MSG_DST_ID_SLOT], CHORD_MSG_DST_ID_SIZE);
  }
  if (size) {
    memcpy(size, &buf[CHORD_MSG_LENGTH_SLOT], CHORD_MSG_LENGTH_SIZE);
  }
  if (content) {
    *content = &buf[CHORD_HEADER_SIZE];
  }
  return CHORD_OK;
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
  while (true) {
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
}

static struct node*
closest_preceeding_node(nodeid_t id)
{
  nodeid_t minabs = __INT_MAX__;
  struct node* retnode = NULL;
  for (int i = 0; i < FINGERTABLE_SIZE; i++) {
    if (!node_is_null(&fingertable[i].node)) {
      nodeid_t finger_abs = chord_abs(fingertable[i].node.id, id);
      if (finger_abs < minabs) {
        minabs = finger_abs;
        retnode = &fingertable[i].node;
      }
    }
  }
  for (int i = 0; i < SUCCESSORLIST_SIZE; i++) {
    if (!node_is_null(&successorlist[i])) {
      nodeid_t finger_abs = chord_abs(successorlist[i].id, id);
      if (finger_abs < minabs) {
        minabs = finger_abs;
        retnode = &successorlist[i];
      }
    }
  }
  return retnode;
}

int
find_successor(struct node* target, struct node* ret, nodeid_t id)
{
  struct node* final = NULL;
  struct node* tmp = target;
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
    DEBUG(ERROR, "Error in notify\n");
    return CHORD_ERR;
  }
  return CHORD_OK;
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
  while (true) {
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

int
handle_ping(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size)
{
  assert(type == MSG_TYPE_PING);
  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshall_msg(
    MSG_TYPE_PONG, src, sizeof(nodeid_t), (unsigned char*)&(mynode.id), msg);
  int ret = chord_send_nonblock_sock(
    sock, msg, CHORD_HEADER_SIZE + sizeof(nodeid_t), src_addr, src_addr_size);
  return ret;
}

int
handle_exit(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size)
{
  assert(type == MSG_TYPE_EXIT);
  assert(data);
  struct node* update = (struct node*)data;
  memcpy(update, data, sizeof(struct node));
  remove_dead_node(update->id);
  if (src == mynode.successor->id && update->id != mynode.id &&
      !node_is_null(update)) {
    copy_node(update, mynode.successor);
  } else if (src == mynode.predecessor->id && update->id != mynode.id &&
             !node_is_null(update)) {
    copy_node(update, mynode.predecessor);
  }
  unsigned char msg[CHORD_HEADER_SIZE];
  marshall_msg(MSG_TYPE_EXIT_ACK, src, 0, NULL, msg);
  int ret = chord_send_nonblock_sock(
    sock, msg, CHORD_HEADER_SIZE, src_addr, src_addr_size);
  return ret;
}

int
handle_find_successor(chord_msg_t type,
                      unsigned char* data,
                      nodeid_t src,
                      int sock,
                      struct sockaddr* src_addr,
                      size_t src_addr_size)
{
  assert(type == MSG_TYPE_FIND_SUCCESSOR ||
         type == MSG_TYPE_FIND_SUCCESSOR_LINEAR);
  nodeid_t req_id;
  chord_msg_t response_type = MSG_TYPE_FIND_SUCCESSOR_RESP;
  memcpy(&req_id, (nodeid_t*)data, sizeof(req_id));
  DEBUG(INFO, "req_id is %d my_id is %d from %d\n", req_id, mynode.id, src);
  struct node successor;
  memset(&successor, 0, sizeof(successor));
  if (req_id == mynode.id) {
    copy_node(mynode.successor, &successor);
  } else if (!node_is_null(mynode.successor) &&
             in_interval(&mynode, mynode.successor, req_id)) {
    copy_node(mynode.successor, &successor);
  } else {
    response_type = MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT;
    if (type == MSG_TYPE_FIND_SUCCESSOR) {
      struct node* next = closest_preceeding_node(req_id);
      copy_node(next, &successor);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_LINEAR) {
      copy_node(mynode.successor, &successor);
    }
  }
  assert(!node_is_null(&successor));
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshall_msg(
    response_type, src, sizeof(struct node), (unsigned char*)&successor, msg);
  int ret = chord_send_nonblock_sock(sock,
                                     msg,
                                     CHORD_HEADER_SIZE + sizeof(struct node),
                                     src_addr,
                                     src_addr_size);
  return ret;
}

int
handle_get_predecessor(chord_msg_t type,
                       unsigned char* data,
                       nodeid_t src,
                       int sock,
                       struct sockaddr* src_addr,
                       size_t src_addr_size)
{
  assert(type == MSG_TYPE_GET_PREDECESSOR);

  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  chord_msg_t response_type;
  size_t size = 0;
  if (!node_is_null(mynode.predecessor)) {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP;
    size = sizeof(struct node);
  } else {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP_NULL;
  }
  marshall_msg(
    response_type, src, size, (unsigned char*)mynode.predecessor, msg);
  return chord_send_nonblock_sock(
    sock, msg, (CHORD_HEADER_SIZE + size), src_addr, src_addr_size);
}

int
handle_notify(chord_msg_t type,
              unsigned char* data,
              nodeid_t src,
              int sock,
              struct sockaddr* src_addr,
              size_t src_addr_size)
{
  assert(type == MSG_TYPE_NOTIFY);

  (void)src;
  (void)sock;
  (void)src_addr;
  (void)src_addr_size;
  struct node n;
  memcpy(&n, data, sizeof(struct node));
  DEBUG(INFO, "get notify from %d curr is: %d\n", n.id, mynode.predecessor->id);
  if (is_pre(n.id)) {
    if (!node_is_null(mynode.predecessor)) {
      DEBUG(INFO,
            "got notify update pre old %d new %d\n",
            mynode.predecessor->id,
            n.id);
    } else {
      DEBUG(INFO, "got notify update pre old nil new %d\n", n.id);
    }
    copy_node(&n, mynode.predecessor);
    assert(mynode.predecessor && n.id == mynode.predecessor->id);
  }
  return CHORD_OK;
}

static int
wait_for_message(struct node* node, unsigned char* retbuf, size_t bufsize)
{
  chord_msg_t type;
  size_t size;
  nodeid_t src_id, dst_id;
  unsigned char* content;
  unsigned char buf[MAX_MSG_SIZE];
  struct sockaddr_storage src_addr;
  socklen_t src_addr_len = sizeof(src_addr);

  int ret = recvfrom(node->socket,
                     buf,
                     MAX_MSG_SIZE,
                     0,
                     (struct sockaddr*)&src_addr,
                     &src_addr_len);
  if (ret < (int)CHORD_HEADER_SIZE) {
    DEBUG(ERROR,
          "Error in recv: %s (recieved) %d < (CHORD_HEADER_SIZE) %d ",
          strerror(errno),
          ret,
          (int)CHORD_HEADER_SIZE);
    close(node->socket);
    return CHORD_ERR;
  }
  demarshall_msg(buf, &type, &src_id, &dst_id, &size, &content);
  DEBUG(INFO,
        "Got %s Request with size %d from %d to %d\n",
        msg_to_string(type),
        (int)size,
        src_id,
        dst_id);
  if (size > 0 && bufsize > 0) {
    if (size < bufsize) {
      bufsize = size;
    }
    memcpy(retbuf, content, bufsize);
  }
  // TODO: Find better solution. Nodes may have another id than hash(1,ip) and
  // thus a new joining node sets the dst_id to CHORD_RING_SIZE to not get
  // dropped.
  if (!(dst_id == mynode.id || dst_id == CHORD_RING_SIZE)) {
    return CHORD_OK;
  }
  switch (type) {
    case MSG_TYPE_FIND_SUCCESSOR_LINEAR:
    case MSG_TYPE_FIND_SUCCESSOR:
      ret = cc.find_successor_handler(type,
                                      content,
                                      src_id,
                                      node->socket,
                                      (struct sockaddr*)&src_addr,
                                      src_addr_len);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR,
              "Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP nonblocking");
      }
      break;
    case MSG_TYPE_PING:
      ret = cc.ping_handler(type,
                            content,
                            src_id,
                            node->socket,
                            (struct sockaddr*)&src_addr,
                            src_addr_len);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in send PONG\n");
      }
      break;
    case MSG_TYPE_EXIT:
      ret = cc.exit_handler(type,
                            content,
                            src_id,
                            node->socket,
                            (struct sockaddr*)&src_addr,
                            src_addr_len);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in send PONG\n");
      }
      break;
    case MSG_TYPE_GET_PREDECESSOR:

      ret = cc.get_predecessor_handler(type,
                                       content,
                                       src_id,
                                       node->socket,
                                       (struct sockaddr*)&src_addr,
                                       src_addr_len);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR,
              "Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT "
              "nonblocking");
      }
      break;

    case MSG_TYPE_NOTIFY:
      cc.notify_handler(type,
                        content,
                        src_id,
                        node->socket,
                        (struct sockaddr*)&src_addr,
                        src_addr_len);
      break;
    case MSG_TYPE_COPY_SUCCESSORLIST: {
      unsigned char msg[CHORD_HEADER_SIZE + sizeof(successorlist)];
      marshall_msg(MSG_TYPE_COPY_SUCCESSORLIST_RESP,
                   src_id,
                   sizeof(successorlist),
                   (unsigned char*)successorlist,
                   msg);
      ret = chord_send_nonblock_sock(node->socket,
                                     msg,
                                     CHORD_HEADER_SIZE + sizeof(successorlist),
                                     (struct sockaddr*)&src_addr,
                                     src_addr_len);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR,
              "Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT "
              "nonblocking");
        DEBUG(ERROR, "");
      }
      break;
    }
    case MSG_TYPE_PUT:
      if (cc.put_handler) {
        cc.put_handler(type,
                       content,
                       src_id,
                       node->socket,
                       (struct sockaddr*)&src_addr,
                       src_addr_len);
      }
      break;
    case MSG_TYPE_GET:
      if (cc.get_handler) {
        cc.get_handler(type,
                       content,
                       src_id,
                       node->socket,
                       (struct sockaddr*)&src_addr,
                       src_addr_len);
      }
      break;
    default:
      break;
  }
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
        if (node->id != pre.id && in_interval(node, node->successor, pre.id) &&
            !is_own_id(pre.id)) {
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
    DEBUG(FATAL, "Error address is null in create node\n");
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
  DEBUG(INFO, "Fix finger %d\n", i);
  if (node->successor && !node_is_null(node->successor) &&
      (node->id != node->successor->id)) {
    DEBUG(INFO,
          "Fix fingers find successor for %d ask: %d\n",
          fingertable[i].start,
          node->successor->id);
    find_successor(
      node,
      &fingertable[i].node,
      ((fingertable[i].start + fingertable[i].interval) % CHORD_RING_SIZE));
    struct node* save = &fingertable[i].node;
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
  int i = 0;
  struct node* node = (struct node*)n;
  while (1) {
    i++;
    DEBUG(INFO, "wait for message run %d\n", i);
    if (wait_for_message(node, NULL, 0) == CHORD_ERR) {
      DEBUG(ERROR, "error in wait_for_message\n");
    }
  }
  return NULL;
}

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
}

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
}

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
    if (node_is_null(node->predecessor)) {
      // memcpy(node->predecessor, &mynode, sizeof(struct node));
    }

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

    if (i % CHORD_CHANGE_INTERVAL == 0 && CHORD_CHANGE_ID &&
        !node_is_null(node->successor) && !node_is_null(node->predecessor)) {

      nodeid_t id = 0;
      struct node save;
      if (get_active_node(node, &id, &save) != CHORD_ERR) {
        if (id > 0 && id != node->id) {
          DEBUG(INFO, "change id to %d bc of %d\n", id, save.id);
          node_exit(node);
          node->id = id;
          if (!is_own_id(save.id)) {
            init_fingertable();
            copy_node(&save, node->successor);
            memset(node->predecessor, 0, sizeof(struct node));
            DEBUG(INFO, "Update successorlist\n");
            update_successorlist(node->successor);
            continue;
          }
        }
      }
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

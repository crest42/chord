
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
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

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
  DEBUG(INFO, "bind %d\n", CHORD_PORT);
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
    memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
  }
  return CHORD_OK;
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
  DEBUG(INFO, "Update successorlist to %d\n", successorlist[0].id);
  mynode.successor = &fingertable[0].node;
  init_fingertable();
  srand(mynode.id);
  first_key = NULL;
  last_key = NULL;
  if (bind_socket(&mynode) == CHORD_ERR) {
    return CHORD_ERR;
  }
  return 0;
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

bool
node_cmp(struct node* first, struct node* second)
{
  if (first->id == second->id && first->successor == second->successor &&
      first->predecessor == second->predecessor) {
    return true;
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
  memset(msg, 0, size);
  assert(msg_type > 0);
  assert(dst_id > 0);

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
  if (!buf) {
    return CHORD_ERR;
  }
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
  unsigned char read_buf[MAX_MSG_SIZE];
  nodeid_t src_id, dst_id;
  size_t msg_size;
  unsigned char* msg_content;
  if (bufsize > CHORD_MSG_MAX_CONTENT_SIZE) {
    bufsize = CHORD_MSG_MAX_CONTENT_SIZE;
  }

  int s = socket(AF_INET6, SOCK_DGRAM, 0);
  if (s == -1) {
    DEBUG(ERROR, "socket");
    return MSG_TYPE_CHORD_ERR;
  }
  DEBUG(DEBUG, "New socket %d\n", s);

  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) <
      0)
    DEBUG(ERROR, "set socket timeout");
  DEBUG(DEBUG, "chord_send_block_and_wait new sock: %d\n", s);
  struct sockaddr_in6 tmpaddr, src_tmpaddr;
  memset(&tmpaddr, 0, sizeof(tmpaddr));

  memcpy(&tmpaddr, &target->addr, sizeof(struct sockaddr_in6));
  assert(tmpaddr.sin6_port == htons(CHORD_PORT));
  memcpy(&src_tmpaddr, &mynode.addr, sizeof(struct sockaddr_in6));
  src_tmpaddr.sin6_port = htons(ntohs(src_tmpaddr.sin6_port) + 1);
  DEBUG(INFO, "bind to %d\n", ntohs(src_tmpaddr.sin6_port));
  if (bind(s, (struct sockaddr*)&src_tmpaddr, sizeof(struct sockaddr_in6)) ==
      -1) {
    DEBUG(ERROR, "bind");
    close(s);
    return MSG_TYPE_CHORD_ERR;
  }
  DEBUG(DEBUG,
        "connect to port %d (id %d)\n",
        ntohs(tmpaddr.sin6_port),
        target->id);
  if (connect(s, (struct sockaddr*)&tmpaddr, sizeof(struct sockaddr_in6)) ==
      -1) {
    close(s);
    DEBUG(ERROR,
          "connect %d sin6_family: %d AF_INET6: %d",
          s,
          tmpaddr.sin6_family,
          AF_INET6);
    return MSG_TYPE_CHORD_ERR;
  }
  int ret = 0;
  while (ret != (int)size) {
    int tmp = sendto(
      s, msg, size, 0, (struct sockaddr*)&tmpaddr, sizeof(struct sockaddr_in6));
    if (tmp < 0) {
      DEBUG(ERROR, "write");
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
  while (true) {
    ret = recv(s, read_buf, MAX_MSG_SIZE, 0);
    if (ret < (int)CHORD_HEADER_SIZE) {
      DEBUG(ERROR,
            "Error in recv (received) %d < (CHORD_HEADER_SIZE) %d",
            ret,
            (int)CHORD_HEADER_SIZE);
      DEBUG(ERROR, "recv");
      close(s);
      return MSG_TYPE_CHORD_ERR;
    }
    demarshall_msg(read_buf, &type, &src_id, &dst_id, &msg_size, &msg_content);
    DEBUG(INFO,
          "Found Msg type %s from %d to %d size %d\n",
          msg_to_string(type),
          src_id,
          dst_id,
          (int)msg_size);
    if (type == wait) {
      DEBUG(INFO,
            "find expected answer %s == %s\n",
            msg_to_string(type),
            msg_to_string(wait));
      break;
    } else {
      DEBUG(INFO,
            "Did not find expected answer %s != %s\n",
            msg_to_string(type),
            msg_to_string(wait));
      break;
    }
  }
  if (msg_size > bufsize) {
    msg_size = bufsize;
  }
  memcpy(buf, msg_content, msg_size);
  close(s);
  return type;
}

static struct node*
find_successor_in_fingertable(nodeid_t nodeid)
{
  struct node* best_match = NULL;
  for (int i = FINGERTABLE_SIZE - 1; i >= 0; i--) {
    if (!node_is_null(&fingertable[i].node) &&
        in_interval_id(fingertable[i].start, fingertable[i].node.id, nodeid)) {
      if (best_match && best_match->id < fingertable[i].node.id) {
        DEBUG(DEBUG,
              "search fingertable for %d would return %d\n",
              nodeid,
              fingertable[i].node.id);
        best_match = &fingertable[i].node;
      }
    }
  }
  for (int i = SUCCESSORLIST_SIZE - 1; i >= 0; i--) {
    if (!node_is_null(&successorlist[i]) && best_match) {
      if (in_interval_id(nodeid, best_match->id, successorlist[i].id) &&
          successorlist[i].id < best_match->id) {
        DEBUG(DEBUG,
              "search successorlist for %d would return %d < %d\n",
              nodeid,
              successorlist[i].id,
              best_match->id);
        best_match = &successorlist[i];
      }
    }
  }
  if (best_match) {
    DEBUG(INFO, "final would return %d\n", best_match->id);
  }
  return best_match;
}

int
find_successor(struct node* target, struct node* ret, nodeid_t id)
{
  struct node* final = NULL;
  struct node tmp;
  int steps = 1;
  while (final == NULL) {
    unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
    marshall_msg(MSG_TYPE_FIND_SUCCESSOR,
                 target->id,
                 sizeof(struct node),
                 (unsigned char*)&id,
                 msg);
    chord_msg_t type =
      chord_send_block_and_wait(target,
                                msg,
                                CHORD_HEADER_SIZE + sizeof(struct node),
                                MSG_TYPE_FIND_SUCCESSOR_RESP,
                                (unsigned char*)ret,
                                sizeof(struct node));
    if (type == MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT) {
      steps++;
      char addr[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &(ret->addr.sin6_addr), addr, INET6_ADDRSTRLEN);
      memset(&tmp, 0, sizeof(tmp));
      create_node(addr, &tmp);
      assert(tmp.id == ret->id);
      target = &tmp;
      DEBUG(INFO, "ask next node %d\n", target->id);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_RESP) {
      final = ret;
      break;
    } else if (type == MSG_TYPE_CHORD_ERR) {
      return CHORD_ERR;
    }
  }
  // According to the Protocol we should always need a maximum of
  // log(CHORD_RING_SIZE) steps TODO: This is not guaranteed (for example if we
  // spawn a large number of nodes in short time) assert(steps <=
  // CHORD_RING_BITS);
  nodeid_t ret_id = ret->id;
  if (ret_id == 0) {
    memset(ret, 0, sizeof(struct node));
    return CHORD_ERR;
  }
  DEBUG(INFO, "Found successor for %d on %d steps\n", id, steps);
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
    return CHORD_OK; // TODO: FIX
  }
  return CHORD_OK;
}

static int
update_successorlist(void)
{
  struct node* last = mynode.successor;
  DEBUG(INFO, "Update Successorlist\n");
  if (last && !node_is_null(last)) {
    for (int i = 0; i < FINGERTABLE_SIZE; i++) {
      DEBUG(INFO,
            "Update successor %d search for %d in %d\n",
            i,
            ((last->id + (1)) % CHORD_RING_SIZE),
            last->id);
      find_successor(
        last, &successorlist[i], ((last->id + (1)) % CHORD_RING_SIZE));
      last = &successorlist[i];
    }
  }
  return CHORD_OK;
}

static int
copy_successorlist(struct node* src)
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
  DEBUG(INFO, "Update successorlist");
  copy_successorlist(src->successor);
  return CHORD_OK;
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
      DEBUG(ERROR, "get msg type %s\n", msg_to_string(type));
      return CHORD_ERR;
    }
  }
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

int
handle_ping(unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size)
{
  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshall_msg(
    MSG_TYPE_PONG, src, sizeof(nodeid_t), (unsigned char*)&(mynode.id), msg);
  int ret = chord_send_nonblock_sock(
    sock, msg, CHORD_HEADER_SIZE + sizeof(nodeid_t), src_addr, src_addr_size);
  return ret;
}

int
handle_find_successor(unsigned char* data,
                      nodeid_t src,
                      int sock,
                      struct sockaddr* src_addr,
                      size_t src_addr_size)
{
  nodeid_t req_id;
  chord_msg_t type = MSG_TYPE_NULL;
  memcpy(&req_id, (nodeid_t*)data, sizeof(req_id));
  DEBUG(DEBUG, "req_id is %d my_id is %d from %d\n", req_id, mynode.id, src);
  struct node* successor = NULL;
  if (!node_is_null(mynode.predecessor) &&
      in_interval(mynode.predecessor, &mynode, req_id)) {
    type = MSG_TYPE_FIND_SUCCESSOR_RESP;
    successor = &mynode;
  } else if (!node_is_null(mynode.successor) &&
             in_interval(&mynode, mynode.successor, req_id)) {
    type = MSG_TYPE_FIND_SUCCESSOR_RESP;
    successor = mynode.successor;
  } else {
    type = MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT;
    successor = find_successor_in_fingertable(req_id);
    if (!successor && !node_is_null(mynode.successor)) {
      DEBUG(INFO, "no pre use original pre %p\n", mynode.successor);
      successor = mynode.successor;
    }
  }
  assert(successor);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshall_msg(type, src, sizeof(struct node), (unsigned char*)successor, msg);
  int ret = chord_send_nonblock_sock(sock,
                                     msg,
                                     CHORD_HEADER_SIZE + sizeof(struct node),
                                     src_addr,
                                     src_addr_size);
  return ret;
}

int
handle_get_predecessor(unsigned char* data,
                       nodeid_t src,
                       int sock,
                       struct sockaddr* src_addr,
                       size_t src_addr_size)
{
  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  chord_msg_t type;
  size_t size = 0;
  if (!node_is_null(mynode.predecessor)) {
    type = MSG_TYPE_GET_PREDECESSOR_RESP;
    size = sizeof(struct node);
  } else {
    type = MSG_TYPE_GET_PREDECESSOR_RESP_NULL;
  }
  marshall_msg(type, src, size, (unsigned char*)mynode.predecessor, msg);
  return chord_send_nonblock_sock(
    sock, msg, (CHORD_HEADER_SIZE + size), src_addr, src_addr_size);
}

int
handle_notify(unsigned char* data,
              nodeid_t src,
              int sock,
              struct sockaddr* src_addr,
              size_t src_addr_size)
{
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
generic_wait(struct node* node, unsigned char* retbuf, size_t bufsize)
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
          "Error in recv (recieved) %d < (CHORD_HEADER_SIZE) %d ",
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
  switch (type) {
    case MSG_TYPE_FIND_SUCCESSOR:
      ret = cc.find_successor_handler(content,
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
      ret = cc.ping_handler(content,
                            src_id,
                            node->socket,
                            (struct sockaddr*)&src_addr,
                            src_addr_len);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in send PONG\n");
      }
      break;
    case MSG_TYPE_GET_PREDECESSOR:

      ret = cc.get_predecessor_handler(content,
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
      cc.notify_handler(content,
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
        cc.put_handler(content,
                       src_id,
                       node->socket,
                       (struct sockaddr*)&src_addr,
                       src_addr_len);
      }
      break;
    case MSG_TYPE_GET:
      if (cc.get_handler) {
        cc.get_handler(content,
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
wait_for_message(struct node* node, unsigned char* retbuf, size_t bufsize)
{
  return generic_wait(node, retbuf, bufsize);
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
                "looks like me->suc->pre is new: %d me: %d\n",
                pre.id,
                mynode.id);
          copy_node(&pre, &fingertable[0].node);
          DEBUG(INFO, "Update successor to %d\n", mynode.successor->id);
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

int
add_node(struct node* node)
{
  if (node) {
    for (int i = 1; i <= 3 && (join(&mynode, node) == CHORD_ERR); i++) {
      DEBUG(ERROR,
            "Unable to join retry in %d seconds(%d/3)\n",
            CHORD_PERIODIC_SLEEP,
            i);
      sleep(CHORD_PERIODIC_SLEEP);
    }
  } else {
    copy_node(&mynode, mynode.successor);
    DEBUG(INFO, "Create new chord ring %d\n", mynode.successor->id);
    for (int i = 0; i < FINGERTABLE_SIZE; i++) {
      if (i > 0) {
        copy_node(mynode.successor, &fingertable[i].node);
      }
      copy_node(mynode.successor, &successorlist[i]);
    }
  }

  return CHORD_OK;
}

static void
fix_fingers(struct node* node)
{
  if (!node->successor) {
    return;
  }
  nodeid_t i = rand() % CHORD_RING_BITS;
  DEBUG(INFO, "Fix finger %d\n", i);
  if (node->successor && !node_is_null(node->successor) &&
      (node->id != node->successor->id)) {
    DEBUG(INFO,
          "Fix fingers find successor for %d ask: %d\n",
          fingertable[i].start,
          node->successor->id);
    find_successor(
      node->successor,
      &fingertable[i].node,
      ((fingertable[i].start + fingertable[i].interval) % CHORD_RING_SIZE));
    struct node* save = &fingertable[i].node;
    if (!node_is_null(save)) {
      while (i + 1 < FINGERTABLE_SIZE - 1 &&
             is_finger(&fingertable[i].node, &fingertable[i + 1])) {
        if (!node_cmp(save, &fingertable[i + 1].node)) {
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
send_ping(struct node* node)
{
  if (node_is_null(node)) {
    // TODO: Remove
    return false;
  }
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshall_msg(MSG_TYPE_PING,
               node->id,
               sizeof(nodeid_t),
               (unsigned char*)(&(mynode.id)),
               msg);
  nodeid_t retid = -1;
  chord_msg_t type =
    chord_send_block_and_wait(node,
                              msg,
                              CHORD_HEADER_SIZE + sizeof(struct node),
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
  return send_ping(node->predecessor);
}

static bool
check_successor(struct node* node)
{
  DEBUG(INFO, "check suc %d\n", node->successor->id);
  return send_ping(node->successor);
}

void*
thread_wait_for_msg(void* n)
{
  int i = 0;
  struct node* node = (struct node*)n;
  while (1) {
    i++;
    if (wait_for_message(node, NULL, 0) == CHORD_ERR) {
      DEBUG(ERROR, "error in wait_for_message\n");
      sleep(1);
      break;
    }
  }
  return NULL;
}

void*
thread_periodic(void* n)
{
  int i = 0, factor = 0, limit = 2;
  struct node* node = (struct node*)n;
  while (1) {
    DEBUG(INFO, "%d: sockid: %d periodic run %d\n", node->id, node->socket, i);
    i++;
    if (!node->successor && node_is_null(node->predecessor)) {
      DEBUG(INFO, "Update successor to %d\n", mynode.id);
      node->successor = &mynode;
      memcpy(node->predecessor, &mynode, sizeof(struct node));
    }

    DEBUG(INFO, "stabilze\n");
    if (stabilize(&mynode) == CHORD_OK) {
      if (factor == limit) {
        DEBUG(INFO, "Update successorlist\n");
        update_successorlist();
        factor = 0;
      } else {
        factor++;
      }
    }

    if (!node_is_null(mynode.predecessor) && !check_predecessor(&mynode)) {
      DEBUG(
        ERROR, "ERROR PRE %d Do not respond to ping\n", mynode.predecessor->id);
      for (int i = 0; i < FINGERTABLE_SIZE; i++) {
        if (!node_is_null(&fingertable[i].node) &&
            fingertable[i].node.id == mynode.predecessor->id) {
          memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
        }
      }
      memset(mynode.predecessor, 0, sizeof(struct node));
    }
    int next_successor = 0;
    while (!check_successor(&mynode)) {
      DEBUG(
        ERROR, "Error: suc %d do not respond to ping\n", mynode.successor->id);
      for (int i = 0; i < FINGERTABLE_SIZE; i++) {
        if (!node_is_null(&fingertable[i].node) &&
            fingertable[i].node.id == mynode.successor->id) {
          memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
        }
      }
      DEBUG(INFO, "Update sucessor to %d\n", successorlist[next_successor].id);
      copy_node(&successorlist[next_successor], mynode.successor);
      next_successor++;
    }
    DEBUG(INFO, "Fix fingers\n");
    fix_fingers(&mynode);
#ifdef DEBUG_ENABLE
    debug_print_node(&mynode, true);
#endif
    sleep(CHORD_PERIODIC_SLEEP);
  }
  return NULL;
}

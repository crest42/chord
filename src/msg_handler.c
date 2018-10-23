#include "../include/chord.h"
#include "../include/network.h"

static nodeid_t
chord_abs(nodeid_t a, nodeid_t b)
{
  if (b < a) {
    return CHORD_RING_SIZE - a + b;
  } else {
    return b - a;
  }
}

static struct node*
closest_preceeding_node(nodeid_t id)
{
  nodeid_t minabs = __INT_MAX__;
  struct fingertable_entry *fingertable = get_fingertable();
  struct node *successorlist = get_successorlist();
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

static bool
is_pre(nodeid_t id)
{
  struct node *mynode =get_own_node();
  assert(mynode);
  if (node_is_null(mynode->predecessor)) {
    return true;
  }
  if (in_interval(mynode->predecessor, mynode, id)) {
    return true;
  }
  return false;
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
  struct node *mynode = get_own_node();
  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshall_msg(
    MSG_TYPE_PONG, src, sizeof(nodeid_t), (unsigned char*)&(mynode->id), msg);
  int ret = chord_send_nonblock_sock(
    sock, msg, CHORD_HEADER_SIZE + sizeof(nodeid_t), src_addr, src_addr_size);
  return ret;
}

int
handle_refresh_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size)
{
  assert(type == MSG_TYPE_REFRESH_CHILD);
  (void)data;
  (void)src;
  (void)sock;
  (void)src_addr;
  (void)src_addr_size;
  struct child* c = (struct child*)data;
  struct childs *childs = get_childs();
  struct node *mynode = get_own_node(), *retnode = mynode;
  struct aggregate *mystats = get_stats();
  time_t systime = time(NULL);
  chord_msg_t ret = MSG_TYPE_CHORD_ERR;
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if(childs->child[i].child == c->child) {
      childs->child[i].t = systime;
      childs->child[i].aggregation = c->aggregation;
      ret = MSG_TYPE_REFRESH_CHILD_OK;
      break;
    }
  }
  if (ret != MSG_TYPE_REFRESH_CHILD_OK) {
    if(c->child < mynode->id) {
      retnode = mynode->predecessor;
    } else {
      retnode = mynode->successor;
    }
    ret = MSG_TYPE_REFRESH_CHILD_REDIRECT;
  }

  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)+ sizeof(struct aggregate)];
  marshall_msg(
    ret, src, sizeof(struct node), (unsigned char *)retnode, msg);
  add_msg_cont((unsigned char *)mystats, msg,sizeof(struct aggregate), CHORD_HEADER_SIZE + sizeof(struct node));

  return chord_send_nonblock_sock(
    sock, msg, sizeof(msg), src_addr, src_addr_size);
  return CHORD_OK;
}

int
handle_register_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            int sock,
            struct sockaddr* src_addr,
            size_t src_addr_size)
{
  assert(type == MSG_TYPE_REGISTER_CHILD);
  struct child* c = (struct child*)data;
  struct node *mynode = get_own_node(), *retnode = mynode;
  struct childs* childs = get_childs();
  struct aggregate* mystats = get_stats();
  time_t systime = time(NULL);
  chord_msg_t ret = MSG_TYPE_CHORD_ERR;
  if (c->parent_suc.id == mynode->id) {
    bool found = false;
    for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
      if(childs->child[i].child == c->child) {
        childs->child[i].t = systime;
        ret = MSG_TYPE_REGISTER_CHILD_OK;
        found = true;
      }
    }
    if(!found) {
      for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
        if (childs->child[i].t < (systime - 2) ||
            childs->child[i].parent == 0 || 
            (mynode->id > CHORD_RING_SIZE/2 && c->parent > childs->child[i].parent) || 
            (mynode->id < CHORD_RING_SIZE/2 && c->parent < childs->child[i].parent)) {
          memcpy(&childs->child[i], c, sizeof(struct child));
          childs->child[i].t = systime;
          found = true;
          ret = MSG_TYPE_REGISTER_CHILD_OK;
          break;
        }
      }
    }
    if(!found) {
      ret = MSG_TYPE_REGISTER_CHILD_EFULL;
      if(c->child > CHORD_RING_SIZE/2) {
        retnode = mynode->successor;
      } else {
        retnode = mynode->predecessor;
      }
    }
  } else {
    ret = MSG_TYPE_REGISTER_CHILD_EWRONG;
  }
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node) + sizeof(struct aggregate)];
  marshall_msg(ret, src, sizeof(struct node), (unsigned char *)retnode, msg);
  add_msg_cont((unsigned char *)mystats, msg,sizeof(struct aggregate), CHORD_HEADER_SIZE + sizeof(struct node));

  return chord_send_nonblock_sock(
    sock, msg, sizeof(msg), src_addr, src_addr_size);
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
  struct node *mynode = get_own_node();
  assert(mynode);
  struct node* update = (struct node*)data;
  memcpy(update, data, sizeof(struct node));
  remove_dead_node(update->id);
  if (src == mynode->successor->id && update->id != mynode->id &&
      !node_is_null(update)) {
    copy_node(update, mynode->successor);
  } else if (src == mynode->predecessor->id && update->id != mynode->id &&
             !node_is_null(update)) {
    copy_node(update, mynode->predecessor);
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
  struct node *mynode = get_own_node();
  assert(mynode);
  nodeid_t req_id;
  chord_msg_t response_type = MSG_TYPE_FIND_SUCCESSOR_RESP;
  memcpy(&req_id, (nodeid_t*)data, sizeof(req_id));
  DEBUG(INFO, "req_id is %d my_id is %d from %d\n", req_id, mynode->id, src);
  struct node successor;
  memset(&successor, 0, sizeof(successor));
  if (req_id == mynode->id) {
    copy_node(mynode->successor, &successor);
  } else if (!node_is_null(mynode->successor) &&
             in_interval(mynode, mynode->successor, req_id)) {
    copy_node(mynode->successor, &successor);
  } else {
    response_type = MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT;
    if (type == MSG_TYPE_FIND_SUCCESSOR) {
      struct node* next = closest_preceeding_node(req_id);
      copy_node(next, &successor);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_LINEAR) {
      copy_node(mynode->successor, &successor);
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
  struct node *mynode = get_own_node();
  assert(mynode);
  if (!node_is_null(mynode->predecessor)) {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP;
    size = sizeof(struct node);
  } else {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP_NULL;
  }
  marshall_msg(
    response_type, src, size, (unsigned char*)mynode->predecessor, msg);
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
  struct node *mynode = get_own_node();
  assert(mynode);
  struct node n;
  memcpy(&n, data, sizeof(struct node));
  DEBUG(INFO, "get notify from %d curr is: %d\n", n.id, mynode->predecessor->id);
  if (is_pre(n.id)) {
    if (!node_is_null(mynode->predecessor)) {
      DEBUG(INFO,
            "got notify update pre old %d new %d\n",
            mynode->predecessor->id,
            n.id);
    } else {
      DEBUG(INFO, "got notify update pre old nil new %d\n", n.id);
    }
    copy_node(&n, mynode->predecessor);
    assert(mynode->predecessor && n.id == mynode->predecessor->id);
  }
  return CHORD_OK;
}
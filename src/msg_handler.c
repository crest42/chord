#include "../include/chord.h"
#include "../include/network.h"
//#include <stdio.h> //TODO:REMOVE
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
  if (node_is_null(mynode->additional->predecessor)) {
    return true;
  }
  if (in_interval(mynode->additional->predecessor, mynode, id)) {
    return true;
  }
  return false;
}

int
handle_ping(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(msg_size > 0);
  assert(type == MSG_TYPE_PING);
  struct node *mynode = get_own_node();
  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshal_msg(
    MSG_TYPE_PONG, src, sizeof(nodeid_t), (unsigned char*)&(mynode->id), msg);
  return chord_send_nonblock_sock(msg, CHORD_HEADER_SIZE + sizeof(nodeid_t), s);
}

int
handle_refresh_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(type == MSG_TYPE_REFRESH_CHILD);
  assert(msg_size > 0);
  struct child* c = (struct child*)data;
  struct childs *childs = get_childs();
  struct node *mynode = get_own_node(), *retnode = mynode;
  struct aggregate *mystats = get_stats();
  time_t systime = time(NULL);
  chord_msg_t ret = MSG_TYPE_REGISTER_CHILD_EWRONG;
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if(childs->child[i].child == c->child) {
      childs->child[i].t = systime;
      childs->child[i].aggregation = c->aggregation;
      ret = MSG_TYPE_REFRESH_CHILD_OK;
      break;
    }
  }

  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)+ sizeof(struct aggregate)];
  marshal_msg(
    ret, src, sizeof(struct node), (unsigned char *)retnode, msg);
  add_msg_cont((unsigned char *)mystats, msg,sizeof(struct aggregate), CHORD_HEADER_SIZE + sizeof(struct node));

  return chord_send_nonblock_sock(msg, sizeof(msg), s);
}

int
handle_register_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(type == MSG_TYPE_REGISTER_CHILD);
  assert(msg_size > 0);
  assert(src > 0);
  struct child* c = (struct child*)data;
  struct node *mynode = get_own_node(), *retnode = mynode;
  struct childs* childs = get_childs();
  struct aggregate* mystats = get_stats();
  time_t systime = time(NULL);
  chord_msg_t ret = MSG_TYPE_REGISTER_CHILD_EFULL;
  bool overloaded = true;
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if (childs->child[i].t < (systime - CHORD_CHILD_TIMEOUT) ||
        childs->child[i].parent == 0 ||
        childs->child[i].child == c->child ||
        ((childs->child[i].child < CHORD_RING_SIZE / 2 &&
          c->child < CHORD_RING_SIZE / 2 &&
          childs->child[i].child < c->child) &&
         in_interval_id(
           childs->child[i].child, c->child, childs->child[i].parent - 1))) {
      memcpy(&childs->child[i], c, sizeof(struct child));
      childs->child[i].t = systime;
      ret = MSG_TYPE_REGISTER_CHILD_OK;
      overloaded = false;
      break;
    }
  }
  //Overloaded remove farthest
  if (overloaded) {
    struct child* farthest = NULL;
    for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
      struct child* tmp = &childs->child[i];
      if(c->child < CHORD_RING_SIZE/2 && tmp->child < CHORD_RING_SIZE/2 && c->child > tmp->child) {
        if(farthest == NULL || tmp->child > farthest->child) {
          farthest = tmp;
        }
      }
    }
    if(farthest) {
      memcpy(farthest, c, sizeof(struct child));
      farthest->t = systime;
      ret = MSG_TYPE_REGISTER_CHILD_OK;
      overloaded = false;
    } else {
      retnode = mynode->additional->predecessor;
      ret = MSG_TYPE_REGISTER_CHILD_REDIRECT;
      overloaded = false;
    }
  }
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node) + sizeof(struct aggregate)];
  marshal_msg(ret, src, sizeof(struct node), (unsigned char *)retnode, msg);
  add_msg_cont((unsigned char *)mystats, msg,sizeof(struct aggregate), CHORD_HEADER_SIZE + sizeof(struct node));
  return chord_send_nonblock_sock(msg, sizeof(msg), s);
  }

int
handle_exit(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(msg_size > 0);
  assert(type == MSG_TYPE_EXIT);
  assert(data);
  struct node *mynode = get_own_node();
  assert(mynode);
  struct node* update = (struct node*)data;
  memcpy(update, data, sizeof(struct node));
  remove_dead_node(update->id);
  if (src == mynode->additional->successor->id && update->id != mynode->id &&
      !node_is_null(update)) {
    copy_node(update, mynode->additional->successor);
  } else if (src == mynode->additional->predecessor->id && update->id != mynode->id &&
             !node_is_null(update)) {
    copy_node(update, mynode->additional->predecessor);
  }
  unsigned char msg[CHORD_HEADER_SIZE];
  marshal_msg(MSG_TYPE_EXIT_ACK, src, 0, NULL, msg);
  return chord_send_nonblock_sock(msg, sizeof(msg), s);
}

int
handle_find_successor(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(type == MSG_TYPE_FIND_SUCCESSOR ||
         type == MSG_TYPE_FIND_SUCCESSOR_LINEAR);
  assert(msg_size > 0);
  struct node *mynode = get_own_node();
  assert(mynode);
  nodeid_t req_id;
  chord_msg_t response_type = MSG_TYPE_FIND_SUCCESSOR_RESP;
  memcpy(&req_id, (nodeid_t*)data, sizeof(req_id));
  DEBUG(DEBUG, "req_id is %d my_id is %d from %d\n", req_id, mynode->id, src);
  struct node successor;
  memset(&successor, 0, sizeof(successor));
  if (!node_is_null(mynode->additional->successor) &&
             in_interval(mynode, mynode->additional->successor, req_id)) {
    copy_node(mynode->additional->successor, &successor);
  } else {
    response_type = MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT;
    if (type == MSG_TYPE_FIND_SUCCESSOR) {
      struct node* next = closest_preceeding_node(req_id);
      copy_node(next, &successor);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_LINEAR) {
      copy_node(mynode->additional->successor, &successor);
    }
  }
  assert(!node_is_null(&successor));
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  marshal_msg(
    response_type, src, sizeof(struct node), (unsigned char*)&successor, msg);
  return chord_send_nonblock_sock(msg, sizeof(msg), s);
}

int
handle_get_predecessor(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(type == MSG_TYPE_GET_PREDECESSOR);
  assert(!data);
  assert(msg_size == 0);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  chord_msg_t response_type;
  size_t size = 0;
  struct node *mynode = get_own_node();
  assert(mynode && mynode->additional);
  if (!node_is_null(mynode->additional->predecessor)) {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP;
    size = sizeof(struct node);
  } else {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP_NULL;
  }
  marshal_msg(
    response_type, src, size, (unsigned char*)mynode->additional->predecessor, msg);
    return chord_send_nonblock_sock(msg, CHORD_HEADER_SIZE+size, s);

}

int
handle_notify(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  assert(type == MSG_TYPE_NOTIFY);
  assert(msg_size == sizeof(struct node));
  (void)src;
  (void)s;
  struct node *mynode = get_own_node();
  assert(mynode);
  struct node n;
  memcpy(&n, data, sizeof(struct node));
  DEBUG(INFO, "get notify from %d curr is: %d\n", n.id, mynode->additional->predecessor->id);
  if (is_pre(n.id)) {
    if (!node_is_null(mynode->additional->predecessor)) {
      DEBUG(INFO,
            "got notify update pre old %d new %d\n",
            mynode->additional->predecessor->id,
            n.id);
    } else {
      DEBUG(INFO, "got notify update pre old nil new %d\n", n.id);
    }
    copy_node(&n, mynode->additional->predecessor);
    assert(mynode->additional->predecessor && n.id == mynode->additional->predecessor->id);
  }
  return CHORD_OK;
}
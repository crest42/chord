#include "../include/chord.h"
#include "../include/network.h"
//#include <stdio.h> //TODO:REMOVE
extern struct node* self;
extern struct childs *self_childs;
extern struct aggregate* mystats;

static bool
is_pre(nodeid_t id)
{
  assert(self);
  if (node_is_null(self->additional->predecessor)) {
    return true;
  }
  if (in_interval(self->additional->predecessor, self, id)) {
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
  (void)type;
  (void)msg_size;
  (void)data;
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshal_msg(
    MSG_TYPE_PONG, src, sizeof(nodeid_t), (unsigned char*)&(self->id), msg);
  return chord_send_nonblock_sock(msg, CHORD_HEADER_SIZE + sizeof(nodeid_t), s);
}

int
handle_refresh_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  (void)type;
  (void)msg_size;
  assert(type == MSG_TYPE_REFRESH_CHILD);
  assert(msg_size > 0);
  struct child* c = (struct child*)data;
  struct node *retnode = self;
  time_t systime = time(NULL);
  chord_msg_t ret = MSG_TYPE_REGISTER_CHILD_EWRONG;
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if(self_childs->child[i].child == c->child) {
      self_childs->child[i].t = systime;
      self_childs->child[i].aggregation = c->aggregation;
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
  (void)type;
  (void)msg_size;
  struct child* c = (struct child*)data;
  struct node *retnode = self;
  time_t systime = time(NULL);
  chord_msg_t ret = MSG_TYPE_REGISTER_CHILD_EFULL;
  bool overloaded = true;
  for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
    if (self_childs->child[i].t < (systime - CHORD_CHILD_TIMEOUT) ||
        self_childs->child[i].parent == 0 ||
        self_childs->child[i].child == c->child ||
        ((self_childs->child[i].child < CHORD_RING_SIZE / 2 &&
          c->child < CHORD_RING_SIZE / 2 &&
          self_childs->child[i].child < c->child) &&
         in_interval_id(
           self_childs->child[i].child, c->child, self_childs->child[i].parent - 1))) {
      if(self_childs->child[i].child != c->child) {
        //printf("overwrite child %d with %d\n",self_childs->child[i].child,c->child);
      }
      memcpy(&self_childs->child[i], c, sizeof(struct child));
      self_childs->child[i].t = systime;
      ret = MSG_TYPE_REGISTER_CHILD_OK;
      overloaded = false;
      break;
    }
  }
  //Overloaded remove farthest
  if (overloaded) {
    struct child* farthest = NULL;
    for (int i = 0; i < CHORD_TREE_CHILDS; i++) {
      struct child* tmp = &self_childs->child[i];
      if(c->child < CHORD_RING_SIZE/2 && tmp->child < CHORD_RING_SIZE/2 && c->child > tmp->child) {
        if(farthest == NULL || tmp->child > farthest->child) {
          farthest = tmp;
        }
      }
    }
    if(farthest) {
      if(farthest->child != c->child) {
        //printf("overwrite child %d with %d\n",farthest->child,c->child);
      }
      memcpy(farthest, c, sizeof(struct child));
      farthest->t = systime;
      ret = MSG_TYPE_REGISTER_CHILD_OK;
      overloaded = false;
    } else {
      if(!node_is_null(self->additional->predecessor)) {
        retnode = self->additional->predecessor;
        ret = MSG_TYPE_REGISTER_CHILD_REDIRECT;
        overloaded = false;
      } else {
        ret = MSG_TYPE_REFRESH_CHILD_OK;
      }
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
  (void)type;
  (void)msg_size;
  assert(self);
  struct node* update = (struct node*)data;
  memcpy(update, data, sizeof(struct node));
  remove_dead_node(update->id);
  if (src == self->additional->successor->id && update->id != self->id &&
      !node_is_null(update)) {
    copy_node(update, self->additional->successor);
  } else if (src == self->additional->predecessor->id && update->id != self->id &&
             !node_is_null(update)) {
    copy_node(update, self->additional->predecessor);
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
  (void)type;
  (void)msg_size;
  assert(self);
  nodeid_t req_id;
  chord_msg_t response_type = MSG_TYPE_FIND_SUCCESSOR_RESP;
  memcpy(&req_id, (nodeid_t*)data, sizeof(req_id));
  DEBUG(DEBUG, "req_id is %d my_id is %d from %d\n", req_id, self->id, src);
  struct node successor;
  memset(&successor, 0, sizeof(successor));
  if (!node_is_null(self->additional->successor) &&
             in_interval(self, self->additional->successor, req_id)) {
    copy_node(self->additional->successor, &successor);
  } else {
    response_type = MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT;
    if (type == MSG_TYPE_FIND_SUCCESSOR) {
      struct node* next = closest_preceeding_node(req_id);
      copy_node(next, &successor);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_LINEAR) {
      copy_node(self->additional->successor, &successor);
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
  (void)type;
  (void)msg_size;
  (void)data;
  assert(type == MSG_TYPE_GET_PREDECESSOR);
  assert(!data);
  assert(msg_size == 0);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(struct node)];
  chord_msg_t response_type;
  size_t size = 0;
  assert(self && self->additional);
  if (!node_is_null(self->additional->predecessor)) {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP;
    size = sizeof(struct node);
  } else {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP_NULL;
  }
  marshal_msg(
    response_type, src, size, (unsigned char*)self->additional->predecessor, msg);
    return chord_send_nonblock_sock(msg, CHORD_HEADER_SIZE+size, s);

}

int
handle_notify(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  (void)type;
  (void)msg_size;
  assert(type == MSG_TYPE_NOTIFY);
  assert(msg_size == sizeof(struct node));
  (void)src;
  (void)s;
  assert(self);
  struct node n;
  memcpy(&n, data, sizeof(struct node));
  DEBUG(INFO, "get notify from %d curr is: %d\n", n.id, self->additional->predecessor->id);
  if (is_pre(n.id)) {
    if (!node_is_null(self->additional->predecessor)) {
      DEBUG(INFO,
            "got notify update pre old %d new %d\n",
            self->additional->predecessor->id,
            n.id);
    } else {
      DEBUG(INFO, "got notify update pre old nil new %d\n", n.id);
    }
    copy_node(&n, self->additional->predecessor);
    assert(self->additional->predecessor && n.id == self->additional->predecessor->id);
  }
  return CHORD_OK;
}
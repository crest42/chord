#include "../include/chord.h"
#include "../include/chord_util.h"
#include "../include/network.h"
//#include <stdio.h> //TODO:REMOVE
extern chord_node_t *self;
extern struct childs *self_childs;
extern chord_aggregation_t* mystats;
extern chord_node_t successorlist[SUCCESSORLIST_SIZE];
extern struct fingertable_entry fingertable[FINGERTABLE_SIZE];
chord_callback msg_handler[32];



static uint32_t
chord_abs(nodeid_t a, nodeid_t b)
{
  if (b < a) {
    return CHORD_RING_SIZE - a + b;
  } else {
    return b - a;
  }
}

static bool
is_pre(nodeid_t id)
{
  assert(self);
  if (node_is_null(get_predecessor())) {
    return true;
  }
  if (in_interval(get_predecessor(), self, id)) {
    return true;
  }
  return false;
}


int init_callbacks(void) {
  memset(msg_handler, 0, sizeof(msg_handler));
  return CHORD_OK;
}

chord_callback get_callback(chord_msg_t number) {
  assert(number >= 0);
  assert(number < 32);
  return msg_handler[number];
}

chord_callback set_callback(chord_msg_t number, chord_callback handler) {
  assert(number >= 0);
  assert(number < 32);
  chord_callback old = msg_handler[number];
  msg_handler[number] = handler;
  return old;
}

int
default_handler(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *s,
            size_t msg_size)
{
  (void)data;
  (void)msg_size;
  int ret = 0;
  switch (type) {
    case MSG_TYPE_COPY_SUCCESSORLIST: {
      unsigned char msg[CHORD_HEADER_SIZE + (sizeof(chord_node_t) * (SUCCESSORLIST_SIZE-1))];
      marshal_msg(MSG_TYPE_COPY_SUCCESSORLIST_RESP,
                   src,
                    (sizeof(chord_node_t) * (SUCCESSORLIST_SIZE-1)),
                   (unsigned char*)successorlist,
                   msg);
      ret = chord_send_nonblock_sock(msg,
                                     sizeof(msg),
                                     s);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR,
              "Error while sending MSG_TYPE_COPY_SUCCESSORLIST_RESP\n");
      }
      break;
    }
    case MSG_TYPE_GET_SUCCESSORLIST_ID: {
      uint32_t offset = 0;
      unsigned char msg[CHORD_HEADER_SIZE + (SUCCESSORLIST_SIZE*sizeof(nodeid_t))];
      marshal_msg(MSG_TYPE_GET_SUCCESSORLIST_ID_RESP,src,offset,NULL,msg);
      offset += CHORD_HEADER_SIZE;
      for(int i = 0;i<SUCCESSORLIST_SIZE;i++) {
        add_msg_cont((unsigned char *)&(successorlist[i].id),msg,sizeof(nodeid_t),offset);
        offset += sizeof(nodeid_t);
      }
      ret = chord_send_nonblock_sock(msg,
                                     sizeof(msg),
                                      s);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error while sending MSG_TYPE_GET_SUCCESSORLIST_ID_RESP");
      }
      break;
    }
    default:
      return CHORD_OK;
      break;
  }
  return CHORD_OK;
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
  chord_node_t *retnode = self;
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

  unsigned char msg[CHORD_HEADER_SIZE + sizeof(chord_node_t)+ sizeof(chord_aggregation_t)];
  marshal_msg(
    ret, src, sizeof(chord_node_t), (unsigned char *)retnode, msg);
  add_msg_cont((unsigned char *)mystats, msg,sizeof(chord_aggregation_t), CHORD_HEADER_SIZE + sizeof(chord_node_t));

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
  chord_node_t *retnode = self;
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
      if(!node_is_null(get_predecessor())) {
        retnode = get_predecessor();
        ret = MSG_TYPE_REGISTER_CHILD_REDIRECT;
        overloaded = false;
      } else {
        ret = MSG_TYPE_REFRESH_CHILD_OK;
      }
    }
  }
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(chord_node_t) + sizeof(chord_aggregation_t)];
  marshal_msg(ret, src, sizeof(chord_node_t), (unsigned char *)retnode, msg);
  add_msg_cont((unsigned char *)mystats, msg,sizeof(chord_aggregation_t), CHORD_HEADER_SIZE + sizeof(chord_node_t));
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
  chord_node_t *update = (chord_node_t *)data;
  memcpy(update, data, sizeof(chord_node_t));
  remove_dead_node(update->id);
  if (src == get_successor()->id && update->id != self->id &&
      !node_is_null(update)) {
    copy_node(update, get_successor());
  } else if (src == get_predecessor()->id && update->id != self->id &&
             !node_is_null(update)) {
    copy_node(update, get_predecessor());
  }
  unsigned char msg[CHORD_HEADER_SIZE];
  marshal_msg(MSG_TYPE_EXIT_ACK, src, 0, NULL, msg);
  return chord_send_nonblock_sock(msg, sizeof(msg), s);
}


/*@null@*/ static chord_node_t *closest_preceeding_node(nodeid_t id)
{
  nodeid_t minabs = __INT_MAX__;
  chord_node_t *retnode = NULL;
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
  chord_node_t successor;
  memset(&successor, 0, sizeof(successor));
  if (!node_is_null(get_successor()) &&
             in_interval(self, get_successor(), req_id)) {
    copy_node(get_successor(), &successor);
  } else {
    response_type = MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT;
    if (type == MSG_TYPE_FIND_SUCCESSOR) {
      chord_node_t *next = closest_preceeding_node(req_id);
      copy_node(next, &successor);
    } else if (type == MSG_TYPE_FIND_SUCCESSOR_LINEAR) {
      copy_node(get_successor(), &successor);
    }
  }
  assert(!node_is_null(&successor));
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(chord_node_t)];
  marshal_msg(
    response_type, src, sizeof(chord_node_t), (unsigned char*)&successor, msg);
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
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(chord_node_t)];
  chord_msg_t response_type;
  size_t size = 0;
  if (!node_is_null(get_predecessor())) {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP;
    size = sizeof(chord_node_t);
  } else {
    response_type = MSG_TYPE_GET_PREDECESSOR_RESP_NULL;
  }
  marshal_msg(
    response_type, src, size, (unsigned char*)get_predecessor(), msg);
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
  assert(msg_size == sizeof(chord_node_t));
  (void)src;
  (void)s;
  assert(self);
  chord_node_t n;
  memcpy(&n, data, sizeof(chord_node_t));
  DEBUG(INFO, "get notify from %d curr is: %d\n", n.id, get_predecessor()->id);
  if (is_pre(n.id)) {
    if (!node_is_null(get_predecessor())) {
      DEBUG(INFO,
            "got notify update pre old %d new %d\n",
            get_predecessor()->id,
            n.id);
    } else {
      DEBUG(INFO, "got notify update pre old nil new %d\n", n.id);
    }
    copy_node(&n, get_predecessor());
    assert(get_predecessor() && n.id == get_predecessor()->id);
  }
  return CHORD_OK;
}
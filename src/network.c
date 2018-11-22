#include "../include/chord.h"
#include "../include/network.h"

extern struct node mynode;
extern struct node *self;
extern struct node successorlist[SUCCESSORLIST_SIZE];

#ifdef POSIX_SOCK
int sock_wrapper_open(struct socket_wrapper *wrapper,struct node *node,struct node *target,int local_port,int remote_port){
  return CHORD_OK;
}
int sock_wrapper_recv(struct socket_wrapper *wrapper,unsigned char *buf, size_t buf_size,int flags) {
  return CHORD_OK;
}
int sock_wrapper_send(struct socket_wrapper *wrapper,unsigned char *buf, size_t buf_size) {
  return CHORD_OK;
}
int sock_wrapper_close(struct socket_wrapper *wrapper) {
  return CHORD_OK;
}
#endif


int addr_to_bin(struct in6_addr *to, const char *from) {
  int ret = inet_pton(AF_INET6, from, to);
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
  return CHORD_OK;
}

int
addr_to_node(struct node* node, const char *addr)
{
  assert(node != NULL);
  assert(addr != NULL);
  return addr_to_bin(&node->addr, addr);
}

int
chord_send_nonblock_sock(unsigned char* msg,
                         size_t size,
                         struct socket_wrapper *s)
{
  return sock_wrapper_send(s, msg, size);
}

int
add_msg_cont(unsigned char* data, unsigned char* to, uint32_t size,size_t size_existing) {
  assert(to != NULL);
  assert(data != NULL);
  assert(size > 0);
  assert(size_existing > 0);
  uint32_t old = 0;
  memcpy(&old, &to[CHORD_MSG_LENGTH_SLOT], sizeof(old));
  uint32_t new = htonl(ntohl(old) + size);
  memcpy(&to[CHORD_MSG_LENGTH_SLOT], &new, CHORD_MSG_LENGTH_SIZE);
  #ifndef NDEBUG
  unsigned char *max = ((to + size_existing) > data) ? (to + size_existing) : data;
  unsigned char *min = (to + size_existing + size) > (data + size) ? to + size_existing + size : data + size;
  assert(max <= min);
  #endif
  memcpy(to + size_existing, data, size);
  return CHORD_OK;
}

int
marshal_msg(chord_msg_t msg_type,
             nodeid_t dst_id,
             size_t size,
             unsigned char* content,
             unsigned char* msg)
{
  assert(msg_type > 0);
  assert(msg != NULL);
  assert(dst_id > 0);
  assert((int)size >= 0);
  uint32_t tmp = 0;
  if (content != NULL && size > 0) {
    memmove(&msg[CHORD_HEADER_SIZE], content, size);
  }
  DEBUG(DEBUG,
        "craft msg %s with size %d from %d to dst: %d\n",
        msg_to_string(msg_type),
        (int)size,
        self->id,
        dst_id);
  tmp = htonl((uint32_t)msg_type);
  memcpy(&msg[CHORD_MSG_COMMAND_SLOT], &tmp, CHORD_MSG_COMMAND_SIZE);
  tmp = htonl((uint32_t)(self->id));
  memcpy(&msg[CHORD_MSG_SRC_ID_SLOT], &tmp, CHORD_MSG_SRC_ID_SIZE);
  tmp = htonl((uint32_t)dst_id);
  memcpy(&msg[CHORD_MSG_DST_ID_SLOT], &tmp, CHORD_MSG_DST_ID_SIZE);
  tmp = htonl((uint32_t)size);
  memcpy(&msg[CHORD_MSG_LENGTH_SLOT], &tmp, CHORD_MSG_LENGTH_SIZE);
  return CHORD_OK;
}

int
demarshal_msg(unsigned char* buf,
               chord_msg_t* type,
               nodeid_t* src_id,
               nodeid_t* dst_id,
               uint32_t* size,
               unsigned char** content)
{
  assert(buf != NULL);
  uint32_t tmp;
  if (type) {
    memcpy(&tmp, &buf[CHORD_MSG_COMMAND_SLOT], CHORD_MSG_COMMAND_SIZE);
    *type = (chord_msg_t)ntohl(tmp);
  }
  if (src_id) {
    memcpy(&tmp, &buf[CHORD_MSG_SRC_ID_SLOT], CHORD_MSG_SRC_ID_SIZE);
    *src_id = (nodeid_t)ntohl(tmp);
  }
  if (dst_id) {
    memcpy(&tmp, &buf[CHORD_MSG_DST_ID_SLOT], CHORD_MSG_DST_ID_SIZE);
    *dst_id = (nodeid_t)ntohl(tmp);
  }
  if (size) {
    memcpy(&tmp, &buf[CHORD_MSG_LENGTH_SLOT], CHORD_MSG_LENGTH_SIZE);
    *size = ntohl(tmp);
  }
  if (content) {
    *content = &buf[CHORD_HEADER_SIZE];
  }
  return CHORD_OK;
}

int
wait_for_message(struct node* node, struct socket_wrapper *s)
{
  (void)node;
  chord_msg_t type;
  uint32_t size;
  nodeid_t src_id, dst_id;
  unsigned char* content;
  unsigned char buf[MAX_MSG_SIZE];

  #ifdef RIOT
  int flags = SOCK_NO_TIMEOUT;
  #else
  int flags = 0;
  #endif
  int ret = sock_wrapper_recv(s, buf, sizeof(buf), flags);
  if (ret < (int)CHORD_HEADER_SIZE) {
    DEBUG(ERROR,
          "Error in recv: %s (recieved) %d < (CHORD_HEADER_SIZE) %d ",
          strerror(errno),
          ret,
          (int)CHORD_HEADER_SIZE);
    return CHORD_ERR;
  }
  demarshal_msg(buf, &type, &src_id, &dst_id, &size, &content);
  DEBUG(INFO,
        "Got %s Request with size %u from %d to %d\n",
        msg_to_string(type),
        (int)size,
        src_id,
        dst_id);
  if(size > (uint32_t)ret) {
    //assert(false);
    return CHORD_OK;
  }
  struct chord_callbacks *cc = get_callbacks();
  switch (type) {
    case MSG_TYPE_FIND_SUCCESSOR_LINEAR:
    case MSG_TYPE_FIND_SUCCESSOR:
      ret = cc->find_successor_handler(type,
                                      content,
                                      src_id,
                                      s,
                                      size);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR,
              "Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP nonblocking");
      }
      break;
    case MSG_TYPE_PING:
      ret = cc->ping_handler(type,
                            content,
                            src_id,
                            s,
                            size);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in send PONG\n");
      }
      break;
          case MSG_TYPE_REGISTER_CHILD:
      ret = cc->register_child_handler(type,
                            content,
                            src_id,
                            s,
                            size);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in REGISTER CHILD\n");
      }
      break;
    case MSG_TYPE_REFRESH_CHILD:
      ret = cc->refresh_child_handler(type,
                            content,
                            src_id,
                            s,
                            size);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in REGISTER CHILD\n");
      }
      break;
    case MSG_TYPE_EXIT:
      ret = cc->exit_handler(type,
                            content,
                            src_id,
                            s,
                            size);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR, "Error in send PONG\n");
      }
      break;
    case MSG_TYPE_GET_PREDECESSOR:

      ret = cc->get_predecessor_handler(type,
                                       NULL,
                                       src_id,
                                       s,
                                       size);
      if (ret == CHORD_ERR) {
        DEBUG(ERROR,
              "Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT "
              "nonblocking");
      }
      break;
    case MSG_TYPE_NOTIFY:
      cc->notify_handler(type,
                        content,
                        src_id,
                        s,
                        size);
      break;
    case MSG_TYPE_SYNC:
      if(cc->sync_handler) {
        cc->sync_handler(type,
                        content,
                        src_id,
                        s,
                        size);
      }
    break;
    case MSG_TYPE_SYNC_REQ_FETCH:
      if(cc->sync_fetch_handler) {
        cc->sync_fetch_handler(type,
                        content,
                        src_id,
                        s,
                        size);
      }
    break;
    case MSG_TYPE_PUT:
      if (cc->put_handler) {
        cc->put_handler(type,
                        content,
                        src_id,
                        s,
                        size);
      }
      break;
    case MSG_TYPE_GET:
      if (cc->get_handler) {
        cc->get_handler(type,
                        content,
                        src_id,
                        s,
                        size);
      }
      break;
    case MSG_TYPE_COPY_SUCCESSORLIST: {
      unsigned char msg[CHORD_HEADER_SIZE + (sizeof(struct node) * (SUCCESSORLIST_SIZE-1))];
      marshal_msg(MSG_TYPE_COPY_SUCCESSORLIST_RESP,
                   src_id,
                    (sizeof(struct node) * (SUCCESSORLIST_SIZE-1)),
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
      marshal_msg(MSG_TYPE_GET_SUCCESSORLIST_ID_RESP,src_id,offset,NULL,msg);
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
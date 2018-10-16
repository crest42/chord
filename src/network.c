#include "../include/chord.h"

int
bind_socket(struct node* node, const char *addr)
{
  int ret = inet_pton(AF_INET6, addr, &(node->addr.sin6_addr));
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
  struct node *mynode = get_own_node();
  assert(mynode);
  assert(mynode->id > 0);

  DEBUG(DEBUG,
        "craft msg %s with size %d from %d to dst: %d\n",
        msg_to_string(msg_type),
        (int)size,
        mynode->id,
        dst_id);
  memcpy(&msg[CHORD_MSG_COMMAND_SLOT], &msg_type, CHORD_MSG_COMMAND_SIZE);
  memcpy(&msg[CHORD_MSG_SRC_ID_SLOT], &(mynode->id), CHORD_MSG_SRC_ID_SIZE);
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
wait_for_message(struct node* node, unsigned char* retbuf, size_t bufsize)
{
  chord_msg_t type;
  size_t size;
  nodeid_t src_id, dst_id;
  unsigned char* content;
  unsigned char buf[MAX_MSG_SIZE];
  struct sockaddr_storage src_addr;
  socklen_t src_addr_len = sizeof(src_addr);
  struct node *mynode = get_own_node();
  assert(mynode);
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
  if (!(dst_id == mynode->id || dst_id == CHORD_RING_SIZE)) {
    //return CHORD_OK;
  }

  struct chord_callbacks *cc = get_callbacks();
  switch (type) {
    case MSG_TYPE_FIND_SUCCESSOR_LINEAR:
    case MSG_TYPE_FIND_SUCCESSOR:
      ret = cc->find_successor_handler(type,
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
      ret = cc->ping_handler(type,
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
      ret = cc->exit_handler(type,
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

      ret = cc->get_predecessor_handler(type,
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
      cc->notify_handler(type,
                        content,
                        src_id,
                        node->socket,
                        (struct sockaddr*)&src_addr,
                        src_addr_len);
      break;
    case MSG_TYPE_COPY_SUCCESSORLIST: {
      struct node *successorlist = get_successorlist();
      unsigned char msg[CHORD_HEADER_SIZE + (sizeof(struct node) * SUCCESSORLIST_SIZE)];
      marshall_msg(MSG_TYPE_COPY_SUCCESSORLIST_RESP,
                   src_id,
                    (sizeof(struct node) * SUCCESSORLIST_SIZE),
                   (unsigned char*)successorlist,
                   msg);
      ret = chord_send_nonblock_sock(node->socket,
                                     msg,
                                     CHORD_HEADER_SIZE +  (sizeof(struct node) * SUCCESSORLIST_SIZE),
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
      if (cc->put_handler) {
        cc->put_handler(type,
                       content,
                       src_id,
                       node->socket,
                       (struct sockaddr*)&src_addr,
                       src_addr_len);
      }
      break;
    case MSG_TYPE_GET:
      if (cc->get_handler) {
        cc->get_handler(type,
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
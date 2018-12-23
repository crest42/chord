#include "../include/chord.h"
#include "../include/network.h"

unsigned char wait_buf[MAX_MSG_SIZE];

extern chord_node_t mynode, *self, successorlist[SUCCESSORLIST_SIZE];
#ifdef POSIX_SOCK
extern size_t read_b;
extern size_t write_b;
#include <sys/socket.h>
int sock_wrapper_open(struct socket_wrapper *wrapper,chord_node_t *node,chord_node_t *target,int local_port,int remote_port){
  wrapper->sock = socket(AF_INET6,SOCK_DGRAM,0);
  wrapper->any = (wrapper->any) ? !wrapper->any : false;
  struct sockaddr_in6 *local = NULL, *remote = NULL;
  if(node) {
    local = &wrapper->local;
    memset( local, 0, sizeof(struct sockaddr_in6) );
    local->sin6_family = AF_INET6;
    local->sin6_port = htons(local_port);
    if(wrapper->any) {
      local->sin6_addr = in6addr_any;
    } else {
      memcpy(&local->sin6_addr,&node->addr,sizeof(struct in6_addr));
    }
    int enable = 1;
    if (setsockopt(wrapper->sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
      DEBUG(ERROR,"setsockopt(SO_REUSEADDR) failed\n");
      return CHORD_ERR;
    }
    if(bind(wrapper->sock, (struct sockaddr *)local, sizeof( struct sockaddr_in6 )) < 0)
    {
      DEBUG(ERROR,"Unable to bind: %s %s %d\n",strerror(errno),buf,wrapper->sock);
      return CHORD_ERR;
    }
  }
  if(target) {
    remote = &wrapper->remote;
    memset( remote, 0, sizeof(struct sockaddr_in6) );
    remote->sin6_family = AF_INET6;
    remote->sin6_port = htons(remote_port);
    memcpy(&remote->sin6_addr,&target->addr,sizeof(struct in6_addr));
    if(connect(wrapper->sock, (struct sockaddr *)remote, sizeof( struct sockaddr_in6 )) < 0)
    {
      DEBUG(ERROR,"Unable to connect: %s",strerror(errno));
      return CHORD_ERR;
    }
  } else {
    memset(&wrapper->remote,0,sizeof(wrapper->remote));
  }
  return CHORD_OK;
}
int sock_wrapper_recv(struct socket_wrapper *wrapper,unsigned char *buf, size_t buf_size,int flags) {
  memset(&wrapper->remote,0,sizeof(wrapper->remote));
  if(flags > 0) {
    struct timeval timeout;
    timeout.tv_sec = flags;
    timeout.tv_usec = 0;
    if (setsockopt(wrapper->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
      DEBUG(ERROR,"setsockopt(SO_REUSEADDR) failed\n");
      return CHORD_ERR;
    }
  }
  socklen_t len = sizeof(wrapper->remote);
  int ret = recvfrom(wrapper->sock,buf,buf_size,0,(struct sockaddr *)&wrapper->remote,&len);
  read_b += ret;
  return ret;
}
int sock_wrapper_send(struct socket_wrapper *wrapper,unsigned char *buf, size_t buf_size) {
  int ret = sendto(wrapper->sock,buf,buf_size,0,(struct sockaddr *)&wrapper->remote,sizeof(wrapper->remote));
  write_b += ret;
  return ret;
}
int sock_wrapper_close(struct socket_wrapper *wrapper) {
  close(wrapper->sock);
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
addr_to_node(chord_node_t *node, const char *addr)
{
  assert(node != NULL);
  assert(addr != NULL);
  return addr_to_bin(&node->addr, addr);
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
  if (content && *size > 0) {
    *content = &buf[CHORD_HEADER_SIZE];
  }
  return CHORD_OK;
}

int
wait_for_message(chord_node_t *node, struct socket_wrapper *s)
{
  (void)node;
  chord_msg_t type;
  uint32_t size;
  nodeid_t src_id, dst_id;
  unsigned char* content = NULL;

  #ifdef RIOT
  int flags = SOCK_NO_TIMEOUT;
  #else
  int flags = 0;
  #endif
  int ret = sock_wrapper_recv(s, wait_buf, sizeof(wait_buf), flags);
  if (ret < (int)CHORD_HEADER_SIZE) {
    DEBUG(ERROR,
          "Error in recv: %s (recieved) %d < (CHORD_HEADER_SIZE) %d ",
          strerror(errno),
          ret,
          (int)CHORD_HEADER_SIZE);
    return CHORD_ERR;
  }
  demarshal_msg(wait_buf, &type, &src_id, &dst_id, &size, &content);
  DEBUG(INFO,
        "Got %s Request with size %u from %d to %d buf: %p\n",
        msg_to_string(type),
        (int)size,
        src_id,
        dst_id,
        (void *)content);
  if(size > (uint32_t)ret) {
    //assert(false);
    return CHORD_OK;
  }
  assert(type >= 0);
  assert(type < 32);
  chord_callback c = get_callback(type);
  if (c == NULL) {
    c = default_handler;
  }
  return c(type, content, src_id, s, size);
}

int
chord_send_block_and_wait(chord_node_t *target,
                          unsigned char* msg,
                          size_t size,
                          chord_msg_t wait,
                          unsigned char* buf,
                          size_t bufsize,
                          size_t *ret_size)
{
  unsigned char read_buf[MAX_MSG_SIZE];
  nodeid_t src_id, dst_id;
  uint32_t msg_size;
  unsigned char* msg_content;
  struct socket_wrapper sock;
  (void)memset(&sock, 0, sizeof(sock));
  sock.any = false;
  int s = sock_wrapper_open(
    &sock, self, target, CHORD_PORT + 1, CHORD_PORT);
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

  ret = sock_wrapper_recv(&sock,read_buf,MAX_MSG_SIZE,TIMEOUT_DEF);

  DEBUG(INFO, "Got %d\n", ret);
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
  DEBUG(INFO,
        "Found Msg type %s (%d) from %d to %d size %d. Wait for: %s (%d)\n",
        msg_to_string(type),
        type,
        src_id,
        dst_id,
        (int)msg_size,
        msg_to_string(wait),
        wait);
  assert((int)type >= 0);
  assert((int)src_id > 0);
  assert((int)dst_id > 0);
  assert((int)msg_size >= 0);
  assert((int)msg_size <= (int)MAX_MSG_SIZE);
  if (msg_size > bufsize) {
    msg_size = bufsize;
  }
  if(buf != NULL) {
    memcpy(buf, msg_content, msg_size);
  }
  if(ret_size)
    *ret_size = msg_size;
  sock_wrapper_close(&sock);
  return type;
}

int
chord_send_nonblock_sock(unsigned char* msg,
                         size_t size,
                         struct socket_wrapper *s)
{
  return sock_wrapper_send(s, msg, size);
}

#include "../include/chord.h"
#include "../include/bootstrap.h"
#include "../include/network.h"

extern struct node* self;
extern struct bootstrap_list bslist;
int
fill_bslist_mcast(const char* addr, uint32_t max, uint32_t timeout)
{
  struct node mcast_node = {.id = 0, .size = 0,.used = 0, .additional = NULL};
  addr_to_node(&mcast_node, addr);
  unsigned char msg[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  unsigned char read_buf[CHORD_HEADER_SIZE + sizeof(nodeid_t)];
  marshal_msg(MSG_TYPE_PING,
              CHORD_RING_SIZE,
              sizeof(nodeid_t),
              (unsigned char*)(&(self->id)),
              msg);
  struct socket_wrapper sock;
  sock.any = false;
  int s = sock_wrapper_open(
    &sock, self, &mcast_node, CHORD_PORT + 1, CHORD_PORT);
  if (s == -1) {
    DEBUG(ERROR, "socket: %s\n", strerror(errno));
    return MSG_TYPE_CHORD_ERR;
  }
  int tmp = sock_wrapper_send(&sock, msg,sizeof(msg));
  if (tmp < 0) {
    DEBUG(ERROR, "write: %s", strerror(errno));
    sock_wrapper_close(&sock);
    return MSG_TYPE_CHORD_ERR;
  }
  uint32_t i = 0;
  while (i<max) {
    int ret = sock_wrapper_recv(&sock, read_buf, sizeof(read_buf), TIMEOUT(timeout));
    if (ret < (int)CHORD_HEADER_SIZE) {
      if(ret < 0) {
        break;
      } else {
        continue;
      }
    }
    chord_msg_t type;
    demarshal_msg(read_buf, &type, NULL, NULL, NULL, NULL);
      if(type == MSG_TYPE_PONG) {
        if(add_node_to_bslist((struct in6_addr*)&sock.remote.addr.ipv6) != CHORD_OK) {
          break;
        }
      }
    i++;
  }
  sock_wrapper_close(&sock);
  return i;
}

int fill_bslist_ll_mcast(uint32_t max, uint32_t timeout) {
  return fill_bslist_mcast("ff02::2",max,timeout);
}

int add_node_to_bslist(struct in6_addr *addr) {
  if (bslist.curr == bslist.size) {
    return CHORD_ERR;
  }
  uint32_t pos = bslist.curr++;
  memcpy(&bslist.list[pos], addr, sizeof(struct in6_addr));
  return CHORD_OK;
}

int add_node_to_bslist_str(const char *addr) {
  struct in6_addr bin_addr;
  memset(&bin_addr, 0, sizeof(bin_addr));
  addr_to_bin(&bin_addr, addr);
  return add_node_to_bslist(&bin_addr);
}
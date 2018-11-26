/**
 * @file network.h
 * @author Robin Lösch
 * @date 10 Oct 2018
 * @brief Function and type definitions for the chord protocol networking
 *
 */
#ifndef _LIBCHORD_NETWORK_H
#define _LIBCHORD_NETWORK_H
#include "msg_handler.h"

int
wait_for_message(chord_node_t *node, struct socket_wrapper *s);
int sock_wrapper_open(struct socket_wrapper *wrapper,/*@null@*/ chord_node_t *node,/*@null@*/ chord_node_t *target,int local_port,int remote_port);
int sock_wrapper_recv(struct socket_wrapper *wrapper,unsigned char *buf, size_t buf_size,int flags);
int sock_wrapper_send(struct socket_wrapper *wrapper,unsigned char *buf, size_t buf_size);
int sock_wrapper_close(struct socket_wrapper *wrapper);

int
addr_to_node(chord_node_t *node, const char *addr);
int
addr_to_bin(struct in6_addr *to, const char *from);

int
demarshal_msg(unsigned char* buf,
               /*@null@*/ /*@out@*/ chord_msg_t *type,
               /*@null@*/ /*@out@*/ nodeid_t *src_id,
               /*@null@*/ /*@out@*/ nodeid_t *dst_id,
               /*@null@*/ /*@out@*/ uint32_t *size,
               /*@null@*/ /*@out@*/ unsigned char **content);
int
marshal_msg(chord_msg_t msg_type,
             nodeid_t dst_id,
             size_t size,
             /*@null@*/ unsigned char* content,
             /*@out@*/ unsigned char* msg);
int
add_msg_cont(unsigned char* data,
             unsigned char* to,
             uint32_t size,
             size_t size_existing);

int
chord_send_block_and_wait(chord_node_t *target,
                          unsigned char *msg,
                          size_t size,
                          chord_msg_t wait,
                          /*@null out@*/  unsigned char *buf,
                          size_t bufsize,
                          /*@null@*/ size_t *ret_size);


/**
 * \brief Sends data non blocking over a socket
 *
 * @param msg msg to send
 * @param size size of the message
 * @param s socket wrapper
 *
 * @return CHORD_OK on successful send, CHORD_ERR otherwise
 */
int
chord_send_nonblock_sock(unsigned char* msg,
                         size_t size,
                         struct socket_wrapper* s);

#endif
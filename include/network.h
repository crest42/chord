/**
 * @file network.h
 * @author Robin Lösch
 * @date 10 Oct 2018
 * @brief Function and type definitions for the chord protocol networking
 *
 */
#ifndef _LIBCHORD_NETWORK_H
#define _LIBCHORD_NETWORK_H

int
wait_for_message(struct node* node, unsigned char* retbuf, size_t bufsize);
int
bind_socket(struct node* node, const char *addr);

int
demarshall_msg(unsigned char* buf,
               chord_msg_t* type,
               nodeid_t* src_id,
               nodeid_t* dst_id,
               size_t* size,
               unsigned char** content);
int
marshall_msg(chord_msg_t msg_type,
             nodeid_t dst_id,
             size_t size,
             unsigned char* content,
             unsigned char* msg);
#endif
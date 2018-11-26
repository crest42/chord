/**
 * @file network.h
 * @author Robin Lösch
 * @date 10 Oct 2018
 * @brief Function for msg handling
 *
 */
#ifndef _LIBCHORD_MSG_HANDLER_H
#define _LIBCHORD_MSG_HANDLER_H

typedef int (*chord_callback)(chord_msg_t,
                              unsigned char*,
                              nodeid_t,
                              struct socket_wrapper *,
                              size_t);

int
init_callbacks(void);

chord_callback
get_callback(chord_msg_t number);

chord_callback
set_callback(chord_msg_t number, chord_callback handler);

int
default_handler(chord_msg_t type,
                unsigned char* data,
                nodeid_t src,
                struct socket_wrapper* s,
                size_t msg_size);

int
handle_ping(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);

int
handle_exit(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);
int
handle_find_successor(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);

int
handle_get_predecessor(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);
int
handle_notify(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);

int
handle_register_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);

int
handle_refresh_child(chord_msg_t type,
            unsigned char* data,
            nodeid_t src,
            struct socket_wrapper *sock,
            size_t msg_size);

#endif
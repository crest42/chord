/**
 * @file bo.otstrap.h
 * @author Robin Lösch
 * @date 17 Nov 2018
 * @brief Function and type definitions for the chord bootstrap protocol
 */
#ifndef _LIBCHORD_BOOTSTRAP_H
#define _LIBCHORD_BOOTSTRAP_H

#define BSLIST_SIZE (16)

struct bootstrap_list {
  uint32_t size;
  uint32_t curr;
  struct in6_addr list[BSLIST_SIZE];
};
int
add_node_to_bslist(struct in6_addr* addr);
int
add_node_to_bslist_str(const char* addr);
int
fill_bslist_ll_mcast(uint32_t max, uint32_t timeout);
int
fill_bslist_mcast(const char* addr, uint32_t max, uint32_t timeout);

#endif
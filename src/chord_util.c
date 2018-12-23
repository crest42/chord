#include "../include/chord.h"
#include "../include/chord_util.h"

extern struct fingertable_entry fingertable[FINGERTABLE_SIZE];
extern chord_node_t successorlist[SUCCESSORLIST_SIZE], *self;

int
remove_dead_node(nodeid_t id)
{
  DEBUG(INFO, "Remove dead node %d\n", id);
  for (int i = 1; i < FINGERTABLE_SIZE; i++) {
    if (fingertable[i].node.id == id) {
      (void)memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
    }
  }
  for (int i = 0; i < SUCCESSORLIST_SIZE; i++) {
    if (successorlist[i].id == id) {
      (void)memset(&successorlist[i], 0, sizeof(successorlist[i]));
    }
  }
  return CHORD_OK;
}


int
copy_node(chord_node_t *node, chord_node_t *copy)
{
  assert(node != NULL);
  assert(copy != NULL);
  assert(copy != self);
  #ifndef NDEBUG
  unsigned char *max = (copy > node) ? (unsigned char *)(copy) : (unsigned char *)node;
  unsigned char *min = (((unsigned char *)copy) + sizeof(chord_node_t)) > (((unsigned char *)node) + sizeof(chord_node_t)) ? ((unsigned char *)copy) + sizeof(chord_node_t) : ((unsigned char *)node) + sizeof(chord_node_t);
  assert(max <= min);
  #endif
  (void)memcpy(copy, node, sizeof(chord_node_t));
  assert(copy->id == node->id);
  assert(memcmp(&node->addr,&copy->addr,sizeof(node->addr)) == 0);
  return CHORD_OK;
}

// euclidean mod because -1 % n should be n-1 not 1
static int
mod(int a, int b)
{
  return ((a % b) + b) % b;
}

bool
in_interval_id(nodeid_t start, nodeid_t end, nodeid_t test)
{
  return (mod((int)(test - start), CHORD_RING_SIZE) <
          mod((int)(end - start), CHORD_RING_SIZE));
}

bool
in_interval(chord_node_t *first, chord_node_t *second, nodeid_t id)
{
  if (!first || !second) {
    return false;
  }
  // We need this because everything is in between x and x
  if (first->id == second->id) {
    return true;
  }
  return in_interval_id(first->id, second->id, id);
}

uint32_t
get_mod_of_hash(unsigned char* hash, int modulo)
{
  //TODO FIX!
  uint32_t r = 0;
  for (int i = 0; i < HASH_DIGEST_SIZE; ++i)
    r = (r * 10 + (uint32_t)hash[i]) % modulo;
  return r;
}

bool
node_is_null(chord_node_t *node)
{
  if (!node) {
    return false;
  }
  if (node->id == 0) {
    return true;
  }
  return false;
}
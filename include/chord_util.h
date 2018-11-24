#ifndef _LIBCHORD_UTIL_H
#define _LIBCHORD_UTIL_H
/**
 * \brief Removes a failing node out of local data structures
 *
 * @param id id of the failing node
 * @return CHORD_OK is removing was successful, CHORD_ERR otherwise
 */
int
remove_dead_node(nodeid_t id);

/**
 * \brief Creates a copy of a node
 *
 * @param node node to copy
 * @param copy target data structure
 *
 * @return CHORD_OK is copy was successful, CHORD_ERR otherwise
 */
int
copy_node(chord_node_t *node, chord_node_t *copy);

/**
 * \brief checks if an id lies between an interval of two nodes
 *
 * check if id is element of [first,second)
 *
 * @return true if id is in interval, false if id is outside of interval
 */
bool
in_interval(chord_node_t *first, chord_node_t *second, nodeid_t id);
bool
in_interval_id(nodeid_t start, nodeid_t end, nodeid_t test);

uint32_t
get_mod_of_hash(unsigned char* hash, int modulo);



/**
 * \brief Finds out if a node is considered as null
 *
 * @param node node to check
 * @return true is node id null, false otherwise
 */
bool
node_is_null(chord_node_t *node);
#endif //_LIBCHORD_UTIL_H
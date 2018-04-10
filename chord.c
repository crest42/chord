#include "chord.h"
#include "chord_internal.h"
#include <errno.h>
#include <unistd.h>
#include <assert.h>


static int is_finger(struct node *n,struct fingertable_entry *entry) {
    if(!n || !entry) {
        return false;
    }
    if(entry->node.id > ((entry->start+entry->interval)%CHORD_RING_SIZE)) {
        if(n->id > (entry->start+entry->interval) && n->id < entry->node.id) {
            return true;
        }
    } else if(entry->node.id < ((entry->start+entry->interval)%CHORD_RING_SIZE)){
        if(n->id < (entry->start+entry->interval) && n->id > entry->node.id) {
            return true;
        }
    }
    return false;
}

static struct node *get_next_successor(void) {
    for (int i = 0; i < FINGERTABLE_SIZE; i++)
    {
                if(successorlist[i].id > mynode.successor->id) {
                    return &successorlist[i];
                }
    }
    return &mynode;
}

bool node_is_null(struct node *node) {
    if(!node) {
        return false;
    }
    if (node->id == 0 && !node->successor && !node->predecessor )
    {
        return true;
    }
    return false;
}
#ifdef DEBUG_ENABLE
static const char *log_level_to_string(enum log_level level){
    switch (level)
    {
        case OFF:
            return "OFF";
        case FATAL:
            return "FATAL";
        case ERROR:
            return "ERROR";
        case WARN:
            return "WARN";
        case INFO:
            return "INFO";
        case DEBUG:
            return "DEBUG";
        case ALL:
            return "ALL";
        default:
            return NULL;
    }
}
#endif
#ifdef DEBUG_ENABLE
static void debug_printf(const char *fname,enum log_level level, const char* format, ... ) {
    if((level & DEBUG_LEVEL) != level) {
        return;
    }
    char max_func_name[DEBUG_MAX_FUNC_NAME];
    memset(max_func_name, 0, DEBUG_MAX_FUNC_NAME);
    strncpy(max_func_name, fname, DEBUG_MAX_FUNC_NAME-1);
    for (int i = strlen(max_func_name); i < DEBUG_MAX_FUNC_NAME-1;i++) {
        max_func_name[i] = ' ';
    }
    printf("[%d|%d] [%s] %s: ",mynode.id,	_getpid(),log_level_to_string(level),max_func_name);
    va_list args;
    va_start( args, format );
    vprintf( format, args );
    va_end( args );
    return;
}
#endif

bool node_cmp(struct node *first, struct node *second) {
    if(first->id == second->id && first->successor == second->successor && first->predecessor== second->predecessor) {
        return true;
    }
    return false;
}

struct node *get_own_node(void) {
    return &mynode;
}

static int copy_node(struct node *node,struct node *copy) {
    memcpy(copy, node, sizeof(struct node));
    assert(copy->addr.sin6_family == node->addr.sin6_family);
    assert(copy->id == node->id);
    return CHORD_OK;
}

int get_mod_of_hash(unsigned char *hash,int modulo) {
    int remainder = 0;
    for (int i = 0;  i < HASH_DIGEST_SIZE; ++i)
    {
        remainder = (remainder * 10 + hash[i]) % modulo;
    }
    return remainder;
}

static int chord_send_nonblock_sock(int sock, unsigned char *msg, size_t size,struct sockaddr* addr,socklen_t addr_len) {
    return sendto(sock, msg, size, 0,addr,addr_len);
}


static void debug_print_fingertable(void) {
    printf("fingertable of %d:\n",mynode.id);
        for (int i = 0; i < FINGERTABLE_SIZE;i++) {
            if(!node_is_null(&fingertable[i].node)) {
                printf("%d-%d: node(%d)\n", fingertable[i].start, (fingertable[i].start + fingertable[i].interval) % CHORD_RING_SIZE,fingertable[i].node.id);
            } else {
                printf("%d-%d: node(nil)\n", fingertable[i].start, (fingertable[i].start + fingertable[i].interval) % CHORD_RING_SIZE);
            }
        }
}
static void debug_print_successorlist(void) {
        printf("successorlist of %d:\n",mynode.id);
        int myid = -1;
        for (int i = 0; i < FINGERTABLE_SIZE; i++)
        {
            if (!node_is_null(mynode.successor))
            {
                myid = ((mynode.successor->id + (i)) % CHORD_RING_SIZE);
            }
            if (!node_is_null(&successorlist[i]))
            {
                printf("successor %d (>%d) is: %d\n", i, myid, successorlist[i].id);
            }
            else
            {
                printf("successor %d (>%d) is: null\n", i,myid);
            }
    }
}

void debug_print_node(struct node *node,bool verbose) {
    if(!node_is_null(node->predecessor)) {
        printf("%d",node->predecessor->id);
    } else {
        printf("NULL");
    }
    printf("<-%d->",node->id);
    if(node->successor) {
        printf("%d",node->successor->id);
    } else {
        printf("NULL");
    }
    printf("\n");
    if(verbose) {
      debug_print_fingertable();
      debug_print_successorlist();
    }
}

static int bind_socket(const char *node_addr,struct node *node) {
    node->socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if(node->socket < 0) {
        perror("Error while creating socket");
        return CHORD_ERR;
    }
    DEBUG(DEBUG,"new sock: %d\n",node->socket);

    int option = 1;
    setsockopt(node->socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    node->addr.sin6_family = AF_INET6;
    node->addr.sin6_port = htons(CHORD_PORT+node->id);
    int ret = inet_pton(AF_INET6, node_addr, &(node->addr.sin6_addr));
    if (ret != 1)
    {
        if(ret == -1) {
            perror("Error in inet_pton");
        }
        else if (ret == 0)
        {
            DEBUG(ERROR,"Addr is not a valid IPv6 address\n");
        }
        else
        {
            DEBUG(ERROR,"Unknown error in inet_pton\n");
        }
        return CHORD_ERR;
    }
    if ((bind(node->socket, (struct sockaddr *)&node->addr, sizeof(node->addr))) == -1)
    {
        perror("Error on bind");
        return CHORD_ERR;
    }
    return CHORD_OK;
}

char *msg_to_string(chord_msg_t msg) {
    switch(msg) {
        case MSG_TYPE_NULL:
            return "MSG_TYPE_NULL";
        case MSG_TYPE_GET_PREDECESSOR:
            return "MSG_TYPE_GET_PREDECESSOR";
        case MSG_TYPE_GET_PREDECESSOR_RESP:
            return "MSG_TYPE_GET_PREDECESSOR_RESP";
        case MSG_TYPE_GET_PREDECESSOR_RESP_NULL:
            return "MSG_TYPE_GET_PREDECESSOR_RESP_NULL";
        case MSG_TYPE_FIND_SUCCESSOR:
            return "MSG_TYPE_FIND_SUCCESSOR";
        case MSG_TYPE_FIND_SUCCESSOR_RESP:
            return "MSG_TYPE_FIND_SUCCESSOR_RESP";
        case MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT:
            return "MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT";
        case MSG_TYPE_GET_SUCCESSOR:
            return "MSG_TYPE_GET_SUCCESSOR";
        case MSG_TYPE_GET_SUCCESSOR_RESP:
            return "MSG_TYPE_GET_SUCCESSOR_RESP";
        case MSG_TYPE_PING:
            return "MSG_TYPE_PING";
        case MSG_TYPE_PONG:
            return "MSG_TYPE_PONG";
        case MSG_TYPE_NO_WAIT:
            return "MSG_TYPE_NO_WAIT";
        case MSG_TYPE_NOTIFY:
            return "MSG_TYPE_NOTIFY";
        case MSG_TYPE_COPY_SUCCESSORLIST:
            return "MSG_TYPE_COPY_SUCCESSORLIST";
        case MSG_TYPE_COPY_SUCCESSORLIST_RESP:
            return "MSG_TYPE_COPY_SUCCESSORLIST_RESP";
        default:
            return "UNKNOWN";
        }
}

static unsigned char *craft_message(chord_msg_t msg_type, nodeid_t dst_id, size_t size, char *content) {
    assert(msg_type > 0);
    assert(dst_id > 0);

    DEBUG(DEBUG,"craft msg %s with size %d from %d to dst: %d\n", msg_to_string(msg_type),(int)size, mynode.id,dst_id);
    unsigned char *msg = calloc(sizeof(char),CHORD_HEADER_SIZE + size);
    if(!msg) {
        return msg;
    }
    memcpy(&msg[CHORD_MSG_COMMAND_SLOT],&msg_type,CHORD_MSG_COMMAND_SIZE);
    memcpy(&msg[CHORD_MSG_SRC_ID_SLOT],&(mynode.id),CHORD_MSG_SRC_ID_SIZE);
    memcpy(&msg[CHORD_MSG_DST_ID_SLOT],&dst_id,CHORD_MSG_DST_ID_SIZE);
    memcpy(&msg[CHORD_MSG_LENGTH_SLOT], &size, CHORD_MSG_LENGTH_SIZE);
    if(content != NULL && size > 0) {
      memcpy(&msg[CHORD_HEADER_SIZE], content, size);
    }
    return msg;
}

static void free_message(unsigned char *msg) {
    free(msg);
}

static int chord_send_block_and_wait(struct node *target, unsigned char *msg, size_t size,chord_msg_t wait, char *buf, size_t bufsize) {
    char read_buf[MAX_MSG_SIZE];
    if(bufsize > CHORD_MSG_MAX_CONTENT_SIZE) {
        bufsize = CHORD_MSG_MAX_CONTENT_SIZE;
    }


    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if(s == -1) {
        perror("socket");
        return CHORD_ERR;
    }

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
        perror("set socket timeout");
    DEBUG(DEBUG, "chord_send_block_and_wait new sock: %d\n", s);
    struct sockaddr_in6 tmpaddr, src_tmpaddr;
    memcpy(&tmpaddr, &target->addr, sizeof(struct sockaddr_in6));
    memcpy(&src_tmpaddr, &mynode.addr, sizeof(struct sockaddr_in6));
    src_tmpaddr.sin6_port += 1;
    errno = 0;
    if(bind(s, (struct sockaddr *)&src_tmpaddr, sizeof(struct sockaddr_in6)) == -1) {
        perror("bind");
        return CHORD_ERR;
    }
    if (connect(s, (struct sockaddr *)&tmpaddr, sizeof(struct sockaddr_in6)) == -1)
    {
        close(s);
        DEBUG(ERROR,"connect %d sin6_family: %d AF_INET6: %d",s,tmpaddr.sin6_family,AF_INET6);
        perror("");
        return CHORD_ERR;
    }
    int ret = 0;
    while (ret != size) {
        int tmp = sendto(s, msg, size, 0, (struct sockaddr *)&tmpaddr, sizeof(struct sockaddr_in6));
        if (tmp < 0)
        {
            perror("write");
            return CHORD_ERR;
      }
      ret += tmp;
    }
    if (wait == MSG_TYPE_NO_WAIT)
    {
        close(s);
        return MSG_TYPE_NO_WAIT;
    }
    chord_msg_t type = 0;
    while (true)
    {
       ret = recv(s, read_buf, MAX_MSG_SIZE, 0);
       if (ret < CHORD_HEADER_SIZE || ret < 0)
       {
           DEBUG(ERROR,"Error in recv (recieved) %d < (CHORD_HEADER_SIZE) %d: ", ret, (int)CHORD_HEADER_SIZE);
           perror("");
            close(s);
           return CHORD_ERR;
        }

        memcpy(&type, &read_buf[CHORD_MSG_COMMAND_SLOT], CHORD_MSG_COMMAND_SIZE);
        #ifdef DEBUG_ENABLE
        nodeid_t src_id = 0, dst_id = 0;
        size_t size = 0;

        memcpy(&src_id, &read_buf[CHORD_MSG_SRC_ID_SLOT], CHORD_MSG_SRC_ID_SIZE);
        memcpy(&size, &read_buf[CHORD_MSG_LENGTH_SLOT], CHORD_MSG_LENGTH_SIZE);
        memcpy(&dst_id, &read_buf[CHORD_MSG_DST_ID_SLOT], CHORD_MSG_DST_ID_SIZE);

        DEBUG(INFO,"Found Msg type %s from %d to %d size %d\n",msg_to_string(type),src_id,dst_id,(int)size);
        #endif
        if (type == wait)
        {
            DEBUG(INFO,"find expected answer %s == %s\n", msg_to_string(type), msg_to_string(wait));
             break;
        } else {
            DEBUG(ERROR,"Did not find expected answer %s != %s\n", msg_to_string(type), msg_to_string(wait));
            break;
        }
    }
    memcpy(buf, &read_buf[CHORD_HEADER_SIZE], bufsize);
    close(s);
    return type;
}

static struct node *find_successor_in_fingertable(nodeid_t nodeid) {
    for (int i = 0; i < FINGERTABLE_SIZE;i++) {
        if(!node_is_null(&fingertable[i].node) && nodeid < fingertable[i].node.id) {
            //return fingertable[i].node;
        }
    }
    return NULL;
}

int find_successor(struct node *target,struct node *ret, nodeid_t id) {
    struct node *final = NULL;
    struct node *tmp = NULL;
    int i = 0;
    while (i == 2 || final == NULL)
    {
        unsigned char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR, target->id, CHORD_FIND_SUCCESSOR_SIZE, (char *)&id);
        if(!msg) {
            free(tmp);
            return CHORD_ERR;
        }
        chord_msg_t type = chord_send_block_and_wait(target, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_SIZE, MSG_TYPE_FIND_SUCCESSOR_RESP, (char *)ret, sizeof(struct node));
        free_message(msg);
        if (type == MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT)
        {
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6,&(ret->addr.sin6_addr),addr,INET6_ADDRSTRLEN);
            if(tmp) {
                free(tmp);
            }
            tmp = create_node(addr);
            target = tmp;
            DEBUG(INFO,"ask next node %d\n", ret->id);
        }
        else if (type == MSG_TYPE_FIND_SUCCESSOR_RESP)
        {
            final = ret;
            break;
        } else if (type == CHORD_ERR) {
            free(tmp);
            return CHORD_ERR;
        }
    }
    free(tmp);
    nodeid_t ret_id = ret->id;
    if(ret_id == 0) {
        memset(ret, 0, sizeof(struct node));
        return CHORD_ERR;
    }
    return CHORD_OK;
}

int notify(struct node *target) {
    unsigned char *msg = craft_message(MSG_TYPE_NOTIFY,target->id, sizeof(struct node),(char *)(&mynode));
    chord_msg_t type = chord_send_block_and_wait(target, msg, CHORD_HEADER_SIZE + sizeof(struct node),MSG_TYPE_NO_WAIT,NULL,0);
    if(type == CHORD_ERR) {
        DEBUG(ERROR,"Error in notify\n");
        free_message(msg);
        return CHORD_OK; //TODO: FIX
    }
    free_message(msg);
    return CHORD_OK;
}

static int update_successorlist(void) {
    struct node *last = mynode.successor;
    DEBUG(INFO,"Update Successorlist\n");
    if (last && !node_is_null(last))
    {
        for (int i = 0; i < FINGERTABLE_SIZE; i++)
        {
            DEBUG(INFO,"Update successor %d search for %d in %d\n",i, ((last->id + (1)) % CHORD_RING_SIZE),last->id);
            find_successor(last, &successorlist[i], ((last->id + (1)) % CHORD_RING_SIZE));
            last = &successorlist[i];
        }
    }
    return CHORD_OK;
}

static int copy_successorlist(struct node *src) {
    unsigned char *msg = craft_message(MSG_TYPE_COPY_SUCCESSORLIST,src->id, sizeof(nodeid_t),(char *)(&(mynode.id)));
    while(true) {
        chord_msg_t type = chord_send_block_and_wait(src, msg, CHORD_HEADER_SIZE+sizeof(nodeid_t), MSG_TYPE_COPY_SUCCESSORLIST_RESP, (char *)(successorlist+1), (sizeof(successorlist)-sizeof(struct node)));
        free_message(msg);
        if (type == MSG_TYPE_COPY_SUCCESSORLIST_RESP)
        {
            memcpy(successorlist, src, sizeof(struct node));
            return CHORD_OK;
        } else {
            DEBUG(DEBUG,"get msg type %s\n", msg_to_string(type));
            return CHORD_ERR;
        }
    }
    return CHORD_OK;
}

nodeid_t join(struct node *src, struct node *target) {
    memset(src->predecessor,0,sizeof(struct node));
    find_successor(target,src->successor, src->id);
    if (node_is_null(src->successor))
    {
        DEBUG(ERROR,"Unable to find successor exit\n");
        exit(1);
    }
    DEBUG(INFO,"Update successorlist");
    copy_successorlist(src->successor);
    notify(src->successor);
    return src->successor->id;
}

/*static struct node *get_successor(struct node *src,struct node *pre) {
    unsigned char *msg = craft_message(MSG_TYPE_GET_SUCCESSOR,src->id, sizeof(nodeid_t),(char *)(&(mynode.id)));
    while(true) {
        chord_msg_t type = chord_send_block_and_wait(src, msg, CHORD_HEADER_SIZE + CHORD_PING_SIZE,MSG_TYPE_GET_SUCCESSOR_RESP,(unsigned char *)pre,sizeof(struct node));
        free_message(msg);
        if (type == MSG_TYPE_GET_SUCCESSOR_RESP)
        {
            return CHORD_ERR;
        } else {
            DEBUG("get msg type %s\n",msg_to_string(type));
        }
    }
}*/

static int get_predecessor(struct node *src,struct node *pre) {
    unsigned char *msg = craft_message(MSG_TYPE_GET_PREDECESSOR,src->id, sizeof(nodeid_t),(char *)(&(mynode.id)));
    while(true) {
        chord_msg_t type = chord_send_block_and_wait(src, msg, CHORD_HEADER_SIZE + CHORD_PING_SIZE, MSG_TYPE_GET_PREDECESSOR_RESP, (char *)pre, sizeof(struct node));
        free_message(msg);
        if (type == MSG_TYPE_GET_PREDECESSOR_RESP)
        {
            return CHORD_OK;
        } else if (type == MSG_TYPE_GET_PREDECESSOR_RESP_NULL) {
            memset(pre, 0, sizeof(struct node));
            return CHORD_OK;
        } else {
            DEBUG(ERROR,"get msg type %s\n", msg_to_string(type));
            return CHORD_ERR;
        }
    }
}

static bool in_interval(struct node *first, struct node *second, nodeid_t id) {
    DEBUG(INFO,"check if in %d <-> %d (%d)\n",first->id,second->id,id);
    if (first->id < second->id && id > first->id && id <= second->id)
    {
        return true;
    }
    if(first->id > second->id && (id > first->id || id <= second->id )) {
        return true;
    }
    if(first->id == second->id) {
        return true;
    }
        return false;
}

static bool is_pre(nodeid_t id) {
    if(node_is_null(mynode.predecessor)) {
        return true;
    }
    if(in_interval(mynode.predecessor,&mynode,id)) {
        return true;
    }
    return false;
}

/*static bool is_suc(nodeid_t id) {
    if(!mynode.successor) {
        return true;
    }
    if(in_interval(&mynode,mynode.successor,id)) {
        return true;
    }
    return false;
}*/

static int generic_wait(struct node *node,unsigned char *retbuf,size_t bufsize) {
    chord_msg_t type = 0;
    size_t size = 0;
    unsigned char buf[MAX_MSG_SIZE];

    struct sockaddr_storage src_addr;
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&src_addr;
    socklen_t src_addr_len=sizeof(src_addr);
    int sock = node->socket;
    int ret = recvfrom(sock, buf, MAX_MSG_SIZE, 0, (struct sockaddr *)&src_addr, &src_addr_len);
    if (ret < CHORD_HEADER_SIZE || ret < 0)
    {
        DEBUG(ERROR,"Error in recv (recieved) %d < (CHORD_HEADER_SIZE) %d: ", ret, (int)CHORD_HEADER_SIZE);
        perror("");
        close(sock);
        return CHORD_ERR;
        }
        nodeid_t src_id = 0;

        memcpy(&type, &buf[CHORD_MSG_COMMAND_SLOT], CHORD_MSG_COMMAND_SIZE);
        memcpy(&src_id, &buf[CHORD_MSG_SRC_ID_SLOT], CHORD_MSG_SRC_ID_SIZE);
        memcpy(&size, &buf[CHORD_MSG_LENGTH_SLOT], CHORD_MSG_LENGTH_SIZE);
        unsigned char *content   =              &buf[CHORD_HEADER_SIZE];
        #ifdef DEBUG_ENABLE
        nodeid_t dst_id = 0;
        memcpy(&dst_id, &buf[CHORD_MSG_DST_ID_SLOT], CHORD_MSG_DST_ID_SIZE);
        DEBUG(DEBUG,"Got %s Request with size %d from %d to %d\n", msg_to_string(type), (int)size,src_id,dst_id);
        #endif
        if(size > 0) {
            if(bufsize > 0) {
                if(size < bufsize) {
                    bufsize = size;
                }
                memcpy(retbuf, content, bufsize);
            }
        }
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), addr, INET6_ADDRSTRLEN);
        switch (type)
        {
        case MSG_TYPE_FIND_SUCCESSOR:
            {
                nodeid_t req_id;
                memcpy(&req_id, (nodeid_t *)content, sizeof(req_id));
                DEBUG(DEBUG,"req_id is %d my_id is %d from %d\n", req_id, mynode.id,src_id);
                if(!node_is_null(mynode.predecessor) && in_interval(mynode.predecessor,&mynode,req_id)) {
                    unsigned char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR_RESP, src_id, sizeof(struct node), (char *)&mynode);
                    int ret = chord_send_nonblock_sock(sock, msg, (int)(CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE), (struct sockaddr *)&src_addr, src_addr_len);
                    free_message(msg);
                    if (ret == -1)
                    {
                        DEBUG(ERROR,"Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP nonblocking");
                        perror("");
                    }
                } else if(!node_is_null(mynode.successor) && in_interval(&mynode,mynode.successor,req_id)) {
                    unsigned char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR_RESP, src_id,  sizeof(struct node), (char *)mynode.successor);
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE, (struct sockaddr *)&src_addr, src_addr_len);
                    free_message(msg);
                    if (ret == -1)
                    {
                        DEBUG(ERROR,"Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP nonblocking");
                        perror("");
                    }
                } else {
                        struct node *pre = find_successor_in_fingertable(req_id);
                        if(!pre && !node_is_null(mynode.successor)) {
                            DEBUG(INFO,"no pre use original pre\n");
                            pre = mynode.successor;
                        } else {
                            return CHORD_ERR;
                        }
                        unsigned char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT, node->id, sizeof(struct node), (char *)pre);
                        int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE, (struct sockaddr *)&src_addr, src_addr_len);
                        free_message(msg);
                        if (ret == -1)
                        {
                            DEBUG(ERROR,"Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                            perror("");
                        }
                }
                break;
            }
            case MSG_TYPE_PING: {
                    unsigned char *msg = craft_message(MSG_TYPE_PONG, src_id,  sizeof(nodeid_t), (char *)&(mynode.id));
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_PING_SIZE, (struct sockaddr *)&src_addr, src_addr_len);
                    if(ret == CHORD_ERR) {
                        DEBUG(ERROR,"Error in send PONG\n");
                    }
                    free_message(msg);
                break;
            }
            case MSG_TYPE_GET_PREDECESSOR:
            {
                if(!node_is_null(mynode.predecessor)) {
                    unsigned char *msg = craft_message(MSG_TYPE_GET_PREDECESSOR_RESP, src_id, sizeof(struct node), (char *)mynode.predecessor);
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE, (struct sockaddr *)&src_addr, src_addr_len);
                    free_message(msg);
                    if (ret == -1)
                    {
                        DEBUG(ERROR,"Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                        perror("");
                    }
                } else {
                    unsigned char *msg = craft_message(MSG_TYPE_GET_PREDECESSOR_RESP_NULL, src_id, 0, NULL);
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE, (struct sockaddr *)&src_addr, src_addr_len);
                    free_message(msg);
                    if (ret == -1)
                    {
                    DEBUG(ERROR,"Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                    perror("");
                    }
                }
                break;
            }
            case MSG_TYPE_NOTIFY:
            {
                struct node n;
                memcpy(&n, content, sizeof(struct node));
                if(is_pre(n.id)) {
                    if(!node_is_null(mynode.predecessor)) {
                        DEBUG(INFO,"update pre old %d new %d\n",mynode.predecessor->id,n.id);
                    } else {
                        DEBUG(INFO,"update pre old nil new %d\n",n.id);
                    }
                    copy_node(&n, mynode.predecessor);
                    assert(mynode.predecessor && n.id == mynode.predecessor->id);
                    debug_print_node(&mynode, false);
                }
                break;

            }
            case MSG_TYPE_COPY_SUCCESSORLIST:
            {
                unsigned char *msg = craft_message(MSG_TYPE_COPY_SUCCESSORLIST_RESP, src_id, sizeof(successorlist), (char *)successorlist);
                int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + sizeof(successorlist), (struct sockaddr *)&src_addr, src_addr_len);
                free_message(msg);
                if (ret == -1)
                {
                    DEBUG(ERROR,"Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                    perror("");
                }
                break;
            }
            default:
                break;
            }
    return CHORD_OK;
}

static int wait_for_message(struct node *node,unsigned char *retbuf,size_t bufsize) {
    return generic_wait(node, retbuf, bufsize);
}

static int stabilize(struct node *node) {
    struct node pre;
    if (!node_is_null(node->successor))
    {
        memset(&pre, 0, sizeof(pre));
        int ret = get_predecessor(node->successor, &pre);
        DEBUG(INFO,"got pre %p %d\n",(void *)&pre,(int)pre.id);
        if (ret != CHORD_ERR)
        {
            if (!node_is_null(&pre))
            {
                if (node->id != pre.id)
                {
                    DEBUG(INFO,"looks like me->suc->pre is new: %d me: %d\n", pre.id, mynode.id);
                    if(node->successor->id != mynode.id) {
                      notify(node->successor);
                    }
                    copy_node(&pre, &fingertable[0].node);
                    DEBUG(INFO,"Update successor to %d\n",mynode.successor->id);
                }
                else if (node_is_null(node->predecessor))
                {
                    memcpy(node->predecessor,node->successor,sizeof(struct node));
                }
                else
                {
                    DEBUG(DEBUG,"looks like me->suc->pre stays the same\n");
                }
            } else {
                memcpy(node->predecessor,node->successor,sizeof(struct node));
            }
        } else {
            DEBUG(INFO,"Could not reach successor, try\n");
            DEBUG(INFO,"Update successorlist to %d\n", successorlist[0].id);
            struct node *new_successor = get_next_successor();
            copy_node(new_successor, mynode.successor);
            return CHORD_ERR;
        }
    }
    return CHORD_OK;
}

static int init_fingertable(nodeid_t id) {
    nodeid_t start = 0;
    nodeid_t interval = 0;
    for (int i = 0; i < FINGERTABLE_SIZE; i++)
    {
        start = (mynode.id + ((1 << i) % CHORD_RING_SIZE)) % CHORD_RING_SIZE;
        interval = (mynode.id + ((1 << (i + 1)) % CHORD_RING_SIZE)) % CHORD_RING_SIZE;
        interval -= start;
        fingertable[i].start = start;
        fingertable[i].interval = interval;
        memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
    }
    return CHORD_OK;
}

int init_chord(const char *node_addr,size_t addr_size){
    memset(&mynode, 0, sizeof(mynode));
    memset(&predecessor, 0, sizeof(predecessor));
    memset(successorlist, 0, sizeof(successorlist));
    unsigned char hash_id[HASH_DIGEST_SIZE];
    hash(hash_id, node_addr, addr_size, HASH_DIGEST_SIZE);
    mynode.id = get_mod_of_hash(hash_id,CHORD_RING_SIZE);
    mynode.predecessor = &predecessor;
    DEBUG(INFO,"Update successorlist to %d\n",successorlist[0].id);
    mynode.successor = &fingertable[0].node;
    init_fingertable(mynode.id);
    bind_socket(node_addr, &mynode);
    srand(mynode.id);
    return 0;
}

struct node *create_node(char *address) {
    if(!address) {
        DEBUG(FATAL,"Error address is null in create node\n");
        return NULL;
    }
    struct node *node = malloc(sizeof(struct node));
    memset(node, 0, sizeof(struct node));

    unsigned char hash_id[HASH_DIGEST_SIZE];
    hash(hash_id,address,strlen(address),sizeof(hash_id));
    node->id = get_mod_of_hash(hash_id,CHORD_RING_SIZE);

    DEBUG(INFO,"create node with addr %s\n",address);
    node->socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if(node->socket < 0) {
        perror("Error while creating socket");
        free(node);
        return NULL;
    }
    DEBUG(INFO,"new sock: %d\n",node->socket);
    struct timeval timeout;      
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    if (setsockopt (node->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
    perror("setsockopt failed\n");
    
    node->addr.sin6_family = AF_INET6;
    node->addr.sin6_port = htons(CHORD_PORT+node->id);
    int c = inet_pton(AF_INET6, address,&(node->addr.sin6_addr));
    if (c != 1)
    {
        if(c == -1) {
            perror("Error in inet_pton");
        }
        else if (c == 0)
        {
            DEBUG(FATAL,"Addr %s is not a valid IPv6 address\n",address);
        }
        else
        {
            DEBUG(FATAL,"Unknown error in inet_pton\n");
        }
        free(node);
        return NULL;
    }
    struct sockaddr_in6 src;
    memcpy(&src, &(mynode.addr), sizeof(src));
    //src.sin6_port = 0;
    bind(node->socket, (struct sockaddr *)&src, sizeof(struct sockaddr_in6));

    return node;
}

int add_node(struct node *node) {
    if(node) {
      join(&mynode,node);
    } else {
        copy_node(&mynode, mynode.successor);
        DEBUG(INFO,"Create new chord ring %d\n",mynode.successor->id);

        for (int i = 0; i < FINGERTABLE_SIZE;i++) {
            if(i > 0) {
              copy_node(mynode.successor, &fingertable[i].node);
            }
            copy_node(mynode.successor, &successorlist[i]);
        }
    }

    return CHORD_OK;
}

static bool send_ping(struct node *node) {
    if(node_is_null(node)) {
        return true;
    }
    unsigned char *msg = craft_message(MSG_TYPE_PING,node->id,CHORD_PING_SIZE,(char *)(&(mynode.id)));
    nodeid_t retid = 0;
    chord_msg_t type = chord_send_block_and_wait(node, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_SIZE, MSG_TYPE_PONG, (char *)&retid, sizeof(nodeid_t));
    free_message(msg);
    if (type == MSG_TYPE_PONG && retid == node->id)
    {
        return true;
    } else {
        return false;
    }
}

static void fix_fingers(struct node *node) {
    if (!node->successor)
    {
        return;
    }
    nodeid_t i = rand() % CHORD_RING_BITS;
    DEBUG(INFO,"Fix finger %d\n",i);
    if (node->successor && !node_is_null(node->successor) && (node->id != node->successor->id))
    {
        DEBUG(INFO,"Fix fingers find successor for %d ask: %d\n", fingertable[i].start, node->successor->id);
        find_successor(node->successor, &fingertable[i].node,((fingertable[i].start+fingertable[i].interval)%CHORD_RING_SIZE));
        struct node *save = &fingertable[i].node;
        if (!node_is_null(save))
        {
            while (i + 1 < FINGERTABLE_SIZE-1 && is_finger(&fingertable[i].node,&fingertable[i + 1]))
            {
                    if (!node_cmp(save, &fingertable[i + 1].node))
                    {
                        DEBUG(INFO,"%d new: %d old: %d\n", i + 1, save->id, fingertable[i + 1].node.id);
                        copy_node(save, &fingertable[i + 1].node);
                    }
                i++;
            }
        }
        else
        {
            DEBUG(ERROR,"finger %d is null\n", i);
        }
    }
}

static bool check_predecessor(struct node *node ){
    return send_ping(node->predecessor);
}

static bool check_successor(struct node *node ){
    return send_ping(node->successor);
}

void *thread_wait_for_msg(void *n){
    int i = 0;
    struct node *node = (struct node *)n;
    while (1)
    {
        i++;
        if(wait_for_message(node, NULL, 0) == CHORD_ERR) {
            DEBUG(ERROR,"error in wait_for_message\n");
            sleep(1);
            break;
        }
    }
    return NULL;
}
void *thread_periodic(void *n){
    int i = 0, factor = 0, limit = 2;
    struct node *node = (struct node *)n;
    while (1)
    {
        DEBUG(INFO,"%d: sockid: %d periodic run %d\n", node->id, node->socket, i);
        i++;
        if(!node->successor && node_is_null(node->predecessor)) {
            DEBUG(INFO,"Update successor to %d\n",mynode.id);
            node->successor = &mynode;
            memcpy(node->predecessor, &mynode, sizeof(struct node));
            //DEBUG(INFO,"send ping to successor\n");
            //send_ping(node->successor);
        }
        if (!node_is_null(node->predecessor))
        {
            //DEBUG(INFO,"send ping to predecessor\n");
            //send_ping(node->predecessor);
        }

        DEBUG(INFO,"stabilze\n");
        stabilize(&mynode);
        if(factor == limit) {
            DEBUG(INFO,"Update successorlist\n");
            update_successorlist();
            factor = 0;
        } else {
            factor++;
        }

        DEBUG(INFO,"check pre\n");
        if (!node_is_null(mynode.predecessor) && !check_predecessor(&mynode))
        {
            DEBUG(ERROR,"ERROR PRE Do not respond to ping\n");
            for (int i = 0; i < FINGERTABLE_SIZE;i++) {
                if(!node_is_null(&fingertable[i].node) && fingertable[i].node.id == mynode.predecessor->id) {
                    memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
                }
            }
            memcpy(mynode.predecessor,&successorlist[0],sizeof(struct node));
        }

        if (!check_successor(&mynode))
        {
            DEBUG(ERROR,"Error: suc do not respond to ping\n");
            for (int i = 0; i < FINGERTABLE_SIZE;i++) {
                if(!node_is_null(&fingertable[i].node) && fingertable[i].node.id == mynode.successor->id) {
                    memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
                }
            }
            DEBUG(INFO,"Update sucessor to %d\n",successorlist[1].id);
            struct node *new_successor = get_next_successor();
            copy_node(new_successor, mynode.successor);
        }
        DEBUG(INFO,"Fix fingers\n");
        fix_fingers(&mynode);
        debug_print_node(&mynode,false);
        sleep(CHORD_PERIODIC_SLEEP);
    }
    return NULL;
}
#include "chord.h"
#include <errno.h>
#include <unistd.h>
#include <assert.h>

bool node_is_null(struct node *node) {
    if(node->id == 0 && node->successor == NULL && node->predecessor == NULL) {
        return true;
    }
    return false;
}

struct node *get_own_node() {
    return &mynode;
}

static int copy_node_static(struct node *node,struct node *copy) {
    memcpy(copy, node, sizeof(struct node));
    return CHORD_OK;
}

static int copy_node(struct node *node,struct node **copy) {
    *copy = malloc(sizeof(struct node));
    copy_node_static(node, *copy);
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

static int chord_send_nonblock_sock(int sock, char *msg, size_t size) {
    return send(sock, msg, size, 0);
}


static void debug_print_fingertable() {
    printf("fingetable of %d:\n",mynode.id);
        for (int i = 0; i < FINGERTABLE_SIZE;i++) {
            if(!node_is_null(&fingertable[i].node)) {
                printf("%d-%d: node(%d)\n", fingertable[i].start, (fingertable[i].start + fingertable[i].interval) % CHORD_RING_SIZE,fingertable[i].node.id);
            } else {
                printf("%d-%d: node(nil)\n", fingertable[i].start, (fingertable[i].start + fingertable[i].interval) % CHORD_RING_SIZE);
            }
        }
}
static void debug_print_successorlist() {
        printf("successorlist of %d:\n",mynode.id);
        int myid = -1;
        for (int i = 0; i < FINGERTABLE_SIZE; i++)
        {
            if (mynode.successor)
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
    if(node->predecessor) {
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
    node->socket = socket(AF_INET6, SOCK_STREAM, 0);
    if(node->socket < 0) {
        perror("Error while creating socket");
        return CHORD_ERR;
    }
    int option = 1;
    setsockopt(node->socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    node->addr.sin6_family = AF_INET6;
    node->addr.sin6_port = htons(CHORD_PORT);
    int ret = inet_pton(AF_INET6, node_addr, &(node->addr.sin6_addr));
    if (ret != 1)
    {
        if(ret == -1) {
            perror("Error in inet_pton");
        }
        else if (ret == 0)
        {
            DEBUG("Addr is not a valid IPv6 address\n");
        }
        else
        {
            DEBUG("Unknown error in inet_pton\n");
        }
        return CHORD_ERR;
    }
    if ((bind(node->socket, (struct sockaddr *)&node->addr, sizeof(node->addr))) == -1)
    {
        perror("Error on bind");
        return CHORD_ERR;
    }
    if(listen(node->socket,CHORD_BACKLOG_SIZE) != 0) {
        perror("Listen");
    }
    return CHORD_OK;
}

char *msg_to_string(chord_msg_t msg) {
    switch(msg) {
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
            return "MSG_TYPE_NOTIFY";
        case MSG_TYPE_NOTIFY:
            return "MSG_TYPE_NOTIFY";
        default:
            return "UNKNOWN";
        }
}

static char *craft_message(chord_msg_t msg_type, nodeid_t dst_id, size_t size, char *content) {
    assert(msg_type > 0);
    assert(dst_id > 0);

    DEBUG("craft msg %s with size %d\n", msg_to_string(msg_type), size);
    char *msg = calloc(sizeof(char),CHORD_HEADER_SIZE + size);
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

static void free_message(char *msg) {
    free(msg);
}

static int chord_send_block_and_wait(struct node *target, char *msg, size_t size,chord_msg_t wait, char *buf, size_t bufsize) {
    char read_buf[MAX_MSG_SIZE];
    if(bufsize > CHORD_MSG_MAX_CONTENT_SIZE) {
        bufsize = CHORD_MSG_MAX_CONTENT_SIZE;
    }

    int s = socket(AF_INET6, SOCK_STREAM, 0);

    struct sockaddr_in6 tmpaddr, src_tmpaddr;
    memcpy(&tmpaddr, &target->addr, sizeof(struct sockaddr_in6));
    memcpy(&src_tmpaddr, &mynode.addr, sizeof(struct sockaddr_in6));
    src_tmpaddr.sin6_port = 0;
    errno = 0;
    bind(s, (struct sockaddr *)&src_tmpaddr, sizeof(struct sockaddr_in6));
    if (connect(s, (struct sockaddr *)&tmpaddr, sizeof(struct sockaddr_in6)) == -1)
    {
        close(s);
        printf("connect %d",s);
        perror("");
        if (errno == ECONNREFUSED)
        {
            return CHORD_ERR;
        }
        return CHORD_ERR;
    } else {
        DEBUG("connect done\n");
    }
    int ret = 0;
    while (ret != size) {
      ret += write(s, msg, size);
    }
    if (wait == MSG_TYPE_NO_WAIT)
    {
        close(s);
        return MSG_TYPE_NO_WAIT;
    }
    chord_msg_t type = 0;
    while (true)
    {
        //REALLY ugly timeout solution. target sys supports afaik no timeout...
        for (int i = 0; i < 3;i++) {
            ret = recv(s, read_buf, MAX_MSG_SIZE, MSG_PEEK | MSG_DONTWAIT);
            if(ret == -1 ) {
                usleep(500);
            } else {
                break;
            }
        }
       if(ret == -1) {
            close(s);
           return CHORD_ERR;
       }
       ret = recv(s, read_buf, MAX_MSG_SIZE, 0);
       if (ret < CHORD_HEADER_SIZE)
       {
           DEBUG("Error in recv (recieved) %d < (CHORD_HEADER_SIZE) %d: ", ret, CHORD_HEADER_SIZE);
           perror("");
            close(s);
           return CHORD_ERR;
        }
        type = (chord_msg_t)read_buf[CHORD_MSG_COMMAND_SLOT];
        #ifdef DEBUG_ENABLE
        nodeid_t src_id = (nodeid_t)read_buf[CHORD_MSG_SRC_ID_SLOT];
        nodeid_t dst_id = (nodeid_t)read_buf[CHORD_MSG_DST_ID_SLOT];
        size_t size = (size_t)read_buf[CHORD_MSG_LENGTH_SLOT];
        DEBUG("Found Msg type %s from %d to %d size %d\n",msg_to_string(type),src_id,dst_id,size);
        #endif
        if (type == wait)
        {
            DEBUG("find expected answer %s == %s\n", msg_to_string(type), msg_to_string(wait));
             break;
        } else {
            DEBUG("Did not find expected answer %s != %s\n", msg_to_string(type), msg_to_string(wait));
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

struct node *find_successor(struct node *target,nodeid_t id) {
    struct node *final = NULL;
    struct node *node = malloc(sizeof (struct node));
    int i = 0;
    while (i == 2 || final == NULL)
    {
        char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR, target->id, CHORD_FIND_SUCCESSOR_SIZE, (char *)&id);
        if(!msg) {
            return NULL;
        }
        chord_msg_t type = chord_send_block_and_wait(target, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_SIZE, MSG_TYPE_FIND_SUCCESSOR_RESP, (char *)node, sizeof(struct node));
        free_message(msg);
        if (type == MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT)
        {
            char *addr = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6,&(node->addr.sin6_addr),addr,INET6_ADDRSTRLEN);
            target = create_node(addr);
            DEBUG("ask next node %d\n",node->id);
        }
        else if (type == MSG_TYPE_FIND_SUCCESSOR_RESP)
        {
            final = node;
            break;
        } else if (type == CHORD_ERR) {
            return NULL;
        }
    }

    nodeid_t ret_id = node->id;
    if(ret_id == 0) {
        return NULL;
    }
    return final;
}

int notify(struct node *target) {
    char *msg = craft_message(MSG_TYPE_NOTIFY,target->id, sizeof(struct node),(char *)(&mynode));
    chord_msg_t type = chord_send_block_and_wait(target, msg, CHORD_HEADER_SIZE + sizeof(struct node),MSG_TYPE_NO_WAIT,NULL,0);
    if(type == CHORD_ERR) {
        printf("Error in notify\n");
    }
    free_message(msg);
    return CHORD_OK;
}

static int update_successorlist() {
    struct node *last = mynode.successor;
    if(last) {
        for (int i = 0; i < FINGERTABLE_SIZE; i++)
        {
            struct node *tmp = find_successor(last, ((last->id + (i)) % CHORD_RING_SIZE));
            if(tmp) {
                copy_node_static(tmp, &successorlist[i]);
            } else {
                memset(&successorlist[i], 0, sizeof(struct node));
            }
            free(tmp);
        }
    }
    return CHORD_OK;
}

nodeid_t join(struct node *src, struct node *target) {
    src->predecessor = NULL;
    src->successor = find_successor(target, src->id);
    if(!src->successor) {
        DEBUG("Unable to find successor exit\n");
        exit(1);
    }
    update_successorlist();
    notify(src->successor);
    return src->successor->id;
}

/*static struct node *get_successor(struct node *src) {
    char *msg = craft_message(MSG_TYPE_GET_SUCCESSOR,src->id, sizeof(nodeid_t),(char *)(&(mynode.id)));
    if(!msg) {
        return NULL;
    }
    struct node *pre = malloc(sizeof(struct node));
    while(true) {
    chord_msg_t type = chord_send_block_and_wait(src, msg, CHORD_HEADER_SIZE + CHORD_PING_SIZE,MSG_TYPE_GET_SUCCESSOR_RESP,(unsigned char *)pre,sizeof(struct node));
    free_message(msg);
    if (type == MSG_TYPE_GET_SUCCESSOR_RESP)
    {
        return pre;
    } else {
        DEBUG("get msg type %s\n",msg_to_string(type));
    }
    }
}*/

static int get_predecessor(struct node *src,struct node **pre) {
    char *msg = craft_message(MSG_TYPE_GET_PREDECESSOR,src->id, sizeof(nodeid_t),(char *)(&(mynode.id)));
    *pre = malloc(sizeof(struct node));
    while(true) {
        chord_msg_t type = chord_send_block_and_wait(src, msg, CHORD_HEADER_SIZE + CHORD_PING_SIZE,MSG_TYPE_GET_PREDECESSOR_RESP,(char *)*pre,sizeof(struct node));
        free_message(msg);
        if (type == MSG_TYPE_GET_PREDECESSOR_RESP)
        {
            return CHORD_OK;
        } else if (type == MSG_TYPE_GET_PREDECESSOR_RESP_NULL) {
            free(*pre);
            *pre = NULL;
            return CHORD_OK;
        } else {
            DEBUG("get msg type %s\n", msg_to_string(type));
            free(*pre);
            *pre = NULL;
            return CHORD_ERR;
        }
    }
}

static bool in_interval(struct node *first, struct node *second, nodeid_t id) {
    DEBUG("check if in %d <-> %d (%d)\n",first->id,second->id,id);
    if (first->id < second->id && id >= first->id && id < second->id)
    {
        return true;
    }
    if(first->id > second->id && (id >= first->id || id < second->id )) {
        return true;
    }
    if(first->id == second->id) {
        return true;
    }
        return false;
}

static bool is_pre(nodeid_t id) {
    if(!mynode.predecessor) {
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
    char buf[MAX_MSG_SIZE];
    while (1)
    {
            struct sockaddr_storage src_addr;
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&src_addr;
    socklen_t src_addr_len=sizeof(src_addr);
        int sock = accept(node->socket, (struct sockaddr *)&src_addr,&src_addr_len);

        if (sock == -1)
        {
            perror("accept");
            return CHORD_ERR;
        }
        int ret = read(sock, buf, MAX_MSG_SIZE);
        if (ret < CHORD_HEADER_SIZE)
        {
            DEBUG("Error in recv (recieved) %d < (CHORD_HEADER_SIZE) %d: ",ret,CHORD_HEADER_SIZE);
            perror("");
            close(sock);
            return CHORD_ERR;
        }
        type = (chord_msg_t)buf[CHORD_MSG_COMMAND_SLOT];
        nodeid_t src_id = (nodeid_t)buf[CHORD_MSG_SRC_ID_SLOT];
        size = (size_t)buf[CHORD_MSG_LENGTH_SLOT];
        char *content = &buf[CHORD_HEADER_SIZE];
        #ifdef DEBUG_ENABLE
        nodeid_t dst_id = (nodeid_t)buf[CHORD_MSG_DST_ID_SLOT];
        DEBUG("Got %s Request with size %d from %d to %d\n", msg_to_string(type), size,src_id,dst_id);
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
                DEBUG("req_id is %d my_id is %d from %d\n", req_id, mynode.id,src_id);
                if(mynode.predecessor && in_interval(mynode.predecessor,&mynode,req_id)) {

                    char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR_RESP, src_id, sizeof(struct node), (char *)&mynode);
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE);
                    free_message(msg);
                    if (ret == -1)
                    {
                        DEBUG("Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP nonblocking");
                        perror("");
                    }
                    DEBUG("sended %s  (%d) size %d\n",msg_to_string(MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT), mynode.id, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE);
                }else if(mynode.successor && in_interval(&mynode,mynode.successor,req_id)) {
                    char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR_RESP, src_id,  sizeof(struct node), (char *)mynode.successor);
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE);
                    free_message(msg);
                    if (ret == -1)
                    {
                        DEBUG("Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP nonblocking");
                        perror("");
                    }
                    DEBUG("sended %s  (%d) size %d\n",msg_to_string(MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT), mynode.id, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE);
                } else {
                        struct node *pre = find_successor_in_fingertable(req_id);
                        if(!pre && mynode.successor) {
                            DEBUG("no pre use original pre\n");
                            pre = mynode.successor;
                        } else {
                            return CHORD_ERR;
                        }
                        struct node *node = create_node(addr);
                        char *msg = craft_message(MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT, node->id, sizeof(struct node), (char *)pre);
                        int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE);
                        free_message(msg);
                        if (ret == -1)
                        {
                            DEBUG("Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                            perror("");
                        }
                        DEBUG("sended %s  (%d) size %d\n",msg_to_string(MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT), pre->id, ret);
                }
                break;
            }
            case MSG_TYPE_PING: {
                    char *msg = craft_message(MSG_TYPE_PONG, src_id,  sizeof(nodeid_t), (char *)&(mynode.id));
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_PING_SIZE);
                    if(ret == CHORD_ERR) {
                        printf("Error in send PONG\n");
                    }
                    free_message(msg);
                break;
            }
            case MSG_TYPE_GET_PREDECESSOR:
            {
                if(mynode.predecessor) {
                    char *msg = craft_message(MSG_TYPE_GET_PREDECESSOR_RESP, src_id, sizeof(struct node), (char *)mynode.predecessor);
                    int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE + CHORD_FIND_SUCCESSOR_RESP_SIZE);
                    free_message(msg);
                    if (ret == -1)
                    {
                    DEBUG("Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                    perror("");
                    }
                } else {
                    char *msg = craft_message(MSG_TYPE_GET_PREDECESSOR_RESP_NULL, src_id, 0, NULL);
                int ret = chord_send_nonblock_sock(sock, msg, CHORD_HEADER_SIZE);
                free_message(msg);
                if (ret == -1)
                {
                  DEBUG("Error while sending MSG_TYPE_FIND_SUCCESSOR_RESP_NEXT nonblocking");
                  perror("");
                }
                }
                break;
            }
            case MSG_TYPE_NOTIFY:
            {
                struct node *n = malloc(sizeof(struct node));
                memcpy(n, content, sizeof(struct node));
                if(is_pre(n->id)) {
                    if(mynode.predecessor) {
                        DEBUG("update pre old %d new %d\n",mynode.predecessor->id,n->id);
                    } else {
                        DEBUG("update pre old nil new %d\n",n->id);
                    }
                    mynode.predecessor = n;
                } else {
                    free(n);
                }
                break;

            }
            default:
                break;
            }
    }
    return CHORD_ERR;
}

static int wait_for_message(struct node *node,unsigned char *retbuf,size_t bufsize) {
    return generic_wait(node, retbuf, bufsize);
}

static int stabilize(struct node *node) {
    if(node->successor) {
        struct node *pre = NULL;
        int ret = get_predecessor(node->successor, &pre);
        DEBUG("got pre %p\n",pre);
        if (ret != CHORD_ERR)
        {
            if (pre)
            {
                if (node->id != pre->id)
                {
                    DEBUG("looks like me->suc->pre is new: %d me: %d\n", pre->id, mynode.id);
                    notify(node->successor);
                    node->successor = pre;
                }
                else if (!node->predecessor)
                {
                    node->predecessor = node->successor;
                }
                else
                {
                    DEBUG("looks like me->suc->pre stays the same\n");
                    free(pre);
                }
            } else {
                node->predecessor = node->successor;
            }
        } else {
            DEBUG("got error\n");
            mynode.successor = &successorlist[0];
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
    hash(mynode.hash_id, node_addr, addr_size, HASH_DIGEST_SIZE);
    mynode.id = get_mod_of_hash(mynode.hash_id,CHORD_RING_SIZE);
    mynode.predecessor = NULL;
    mynode.successor = NULL;
    init_fingertable(mynode.id);
    memset(successorlist, 0, sizeof(successorlist));
    bind_socket(node_addr, &mynode);
    srand(mynode.id);
    DEBUG("id: %d\n",mynode.id);
    return 0;
}

struct node *create_node(char *address) {
    if(!address) {
        DEBUG("Error address is null in create node\n");
        return NULL;
    }
    DEBUG("create node with addr %s\n",address);
    struct node *node = malloc(sizeof(struct node));
    memset(node, 0, sizeof(struct node));
    node->socket = socket(AF_INET6, SOCK_STREAM, 0);
    if(node->socket < 0) {
        perror("Error while creating socket");
        return NULL;
    }
    node->addr.sin6_family = AF_INET6;
    node->addr.sin6_port = htons(CHORD_PORT);
    int c = inet_pton(AF_INET6, address,&(node->addr.sin6_addr));
    if (c != 1)
    {
        if(c == -1) {
            perror("Error in inet_pton");
        }
        else if (c == 0)
        {
            DEBUG("Addr is not a valid IPv6 address\n");
        }
        else
        {
            DEBUG("Unknown error in inet_pton\n");
        }
        return NULL;
    }
    struct sockaddr_in6 src;
    memcpy(&src, &(mynode.addr), sizeof(src));
    src.sin6_port = 0;
    bind(node->socket, (struct sockaddr *)&src,sizeof(struct sockaddr_in6));
    hash(node->hash_id,address,sizeof(address),sizeof(node->hash_id));
    node->id = get_mod_of_hash(node->hash_id,CHORD_RING_SIZE);

    return node;
}

int add_node(struct node *node) {
    if(node) {
      join(&mynode,node);
    } else {
        mynode.successor = &mynode;
    }
    return CHORD_OK;
}

static bool send_ping(struct node *node) {
    if(!node) {
        return true;
    }
    char *msg = craft_message(MSG_TYPE_PING,CHORD_PING_SIZE,node->id,(char *)(&(mynode.id)));
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
    if(!node->successor) {
        return;
    }
    nodeid_t i = rand() % CHORD_RING_BITS;
        if(node->successor && (node->id != node->successor->id)) {
            struct node *tmp = find_successor(node->successor, fingertable[i].start);
            if(tmp) {
              copy_node_static(tmp, &fingertable[i].node);
            } else {
              memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
            }
            free(tmp);
            struct node *save = &fingertable[i].node;
            if (!node_is_null(&fingertable[i].node))
            {
                while (i + 1 <= FINGERTABLE_SIZE && fingertable[i].node.id >= fingertable[i + 1].start)
                {
                    if(save) {
                      copy_node_static(save,&fingertable[i + 1].node);
                    } else {
                        memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
                    }
                    i++;
                }
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
        DEBUG("%d: sockid: %d waitloop run %d\n",node->id,node->socket,i);
        i++;
        if(wait_for_message(node, NULL, 0) == CHORD_ERR) {
            DEBUG("error in wait_for_message\n");
            sleep(1);
            break;
        }
    }
    return NULL;
}
void *thread_periodic(void *n){
    int i = 0, factor = 0, limit = 5;
    struct node *node = (struct node *)n;
    while (1)
    {
        i++;
        DEBUG("%d: sockid: %d periodic run %d\n",node->id,node->socket,i);
        if(!node->successor && !node->predecessor) {
            node->successor = &mynode;
            node->predecessor = &mynode;
            //DEBUG("send ping to successor\n");
            //send_ping(node->successor);
        }
        if(node->predecessor) {
            //DEBUG("send ping to predecessor\n");
            //send_ping(node->predecessor);
        }
        DEBUG("periodic: stabilze\n");
        stabilize(&mynode);
        if(factor == limit) {
            DEBUG("Update successorlist\n");
            update_successorlist();
            factor = 0;
        } else {
            factor++;
        }
        DEBUG("periodic: check pre\n");
        if (!check_predecessor(&mynode))
        {
            DEBUG("ERROR PRE Do not respond to ping\n");
            for (int i = 0; i < FINGERTABLE_SIZE;i++) {
                if(!node_is_null(&fingertable[i].node) && fingertable[i].node.id == mynode.predecessor->id) {
                    memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
                }
            }
            mynode.predecessor = &successorlist[0];
        }
        if (!check_successor(&mynode))
        {
            DEBUG("ERROR SUC Do not respond to ping\n");
            for (int i = 0; i < FINGERTABLE_SIZE;i++) {
                if(!node_is_null(&fingertable[i].node) && fingertable[i].node.id == mynode.successor->id) {
                    memset(&fingertable[i].node, 0, sizeof(fingertable[i].node));
                }
            }
            mynode.successor = &successorlist[0];
        }
        fix_fingers(&mynode);
        debug_print_node(&mynode,true);
        sleep(CHORD_PERIODIC_SLEEP);
    }
    return NULL;
}

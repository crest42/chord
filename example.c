#include <stdio.h>
#include <pthread.h>
#include "chord.h"
#include <signal.h>
#include <openssl/sha.h>
#include <unistd.h>
int hash(unsigned char *out, const char *in,size_t in_size,size_t out_size){
    SHA1(in, in_size, out);
}

struct node *n;

static void intHandler(int dummy) {
    printf("close socket %d\n",n->socket);
    close(n->socket);
    close(n->successor->socket);
    close(n->predecessor->socket);
    exit(0);
}

int main(int argc, char *argv[]) {
    if(!argv[1]) {
        printf("need ipv6 as argv[1]\n");
        return 1;
    }
    signal(SIGINT, intHandler);
    char *nodeip = argv[1];
    char *masterip = "2001:4c50:14d:6500:8706:841d:858f:cb2d";
    init_chord(nodeip, strlen(nodeip));

    struct node *mynode = get_own_node();
    n = mynode;
    printf("nodekey for %s is: %d", nodeip,mynode->id);
    for (int i = 0; i < HASH_DIGEST_SIZE; i++)
    {
        printf("%x",mynode->hash_id[i]);
    }
    printf("\n");

    if(strcmp(nodeip,masterip) == 0) {
        add_node(NULL);
    }
    else
    {
        struct node *partner = create_node(masterip);
        printf("no master node here connect to %s\n",masterip);
        add_node(partner);
    }
    pthread_t mythread1;
    pthread_t mythread2;
    void *ret;
    printf("create eventloop thread\n");
    pthread_create(&mythread1, NULL, thread_wait_for_msg, (void *)mynode);
    pthread_create(&mythread2, NULL, thread_periodic, (void *)mynode);

    printf("wait for eventloop thread\n");
    pthread_join(mythread1,&ret);
    pthread_join(mythread2,&ret);
}
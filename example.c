#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include "chord.h"
#include <signal.h>
#include <openssl/sha.h>
#include <unistd.h>
int hash(unsigned char *out, const char *in,size_t in_size,size_t out_size){
    printf("out size: %lu\n",out_size);
    SHA1((unsigned char *)in, in_size, out);
    return 0;
}

int sigint = false;
pthread_t mythread1;
pthread_t mythread2;

void sig_handler(int signo)
{
  if (signo == SIGINT) {
      sigint = true;
  }
}

static void print_usage(void) {
    printf("Usage\n\t./example master <bind addr>\n\t./example slave <master addr>\n");
}
int main(int argc, char *argv[]) {
    if(argc < 1) {
        print_usage();
        return -1;
    }
    char buf[INET6_ADDRSTRLEN];
    char nodeip[INET6_ADDRSTRLEN];
    memset(nodeip, 0, INET6_ADDRSTRLEN);
    char masterip[INET6_ADDRSTRLEN];
    memset(masterip, 0, INET6_ADDRSTRLEN);
    //bool master = false, slave = false;
    struct node *partner = NULL;

    if(!argv[1] || !(strcmp(argv[1],"master") == 0 || strcmp(argv[1],"slave") == 0) || !argv[2] || !inet_pton(AF_INET6, argv[2], buf)) {
        print_usage();
        return 1;
    }
    if(strcmp(argv[1],"slave") == 0 && (!argv[3] || !inet_pton(AF_INET6, argv[3], buf))) {
        print_usage();
        return 1;
    }
    if(strcmp(argv[1],"slave") == 0) {
      memcpy(nodeip, argv[2], INET6_ADDRSTRLEN-1);
      memcpy(masterip, argv[3], INET6_ADDRSTRLEN-1);
    }
    else if (strcmp(argv[1], "master") == 0)
    {
      memcpy(nodeip, argv[2], INET6_ADDRSTRLEN-1);
      memcpy(masterip, argv[2], INET6_ADDRSTRLEN-1);
    }

    if(init_chord(nodeip) == CHORD_ERR) {
        return -1;
    }
    struct node *mynode = get_own_node();
    printf("nodekey for %s is: %d\n", nodeip,mynode->id);

    if(strcmp(nodeip,masterip) == 0) {
        printf("Create new ring\n");
        add_node(NULL);
    }
    else
    {
        printf("no master node here connect to %s\n",masterip);
        partner = create_node(masterip);
        add_node(partner);
    }
    printf("create eventloop thread\n");
    pthread_create(&mythread1, NULL, thread_wait_for_msg, (void *)mynode);
    printf("create periodic thread\n");
    pthread_create(&mythread2, NULL, thread_periodic, (void *)mynode);

    signal(SIGINT, sig_handler);
    while(!sigint) {
        sleep(1);
    }
    free(partner);
    printf("wait for eventloop thread\n");
    if(pthread_cancel(mythread1) != 0) {
        printf("Error cancle thread 1\n");
    }
    if(pthread_cancel(mythread2) != 0) {
        printf("Error cancle thread 2s\n");
    }
    printf("FINAL: ");
    debug_print_node(mynode, false);
    fflush(stdout);
    pthread_join(mythread1,NULL);
    pthread_join(mythread2,NULL);
}
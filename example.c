#include "chord.h"
#include <openssl/sha.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
int
hash(unsigned char* out, const char* in, size_t in_size, size_t out_size)
{
  (void)(out_size);
  SHA1((unsigned char*)in, in_size, out);
  return 0;
}

int sigint = false;
pthread_t mythread1;
pthread_t mythread2;

void
sig_handler(int signo)
{
  if (signo == SIGINT) {
    sigint = true;
  }
}

static void
print_usage(void)
{
  printf(
    "Usage\n\t./example master <bind addr>\n\t./example slave <master addr>\n");
}
int
main(int argc, char* argv[])
{
  if (argc < 1) {
    print_usage();
    return -1;
  }
  char buf[INET6_ADDRSTRLEN];
  char nodeip[INET6_ADDRSTRLEN];
  memset(nodeip, 0, INET6_ADDRSTRLEN);
  char masterip[INET6_ADDRSTRLEN];
  memset(masterip, 0, INET6_ADDRSTRLEN);
  // bool master = false, slave = false;
  struct node* partner = malloc(sizeof(struct node));
  bool silent = false;
  if (!argv[1] ||
      !(strcmp(argv[1], "master") == 0 || strcmp(argv[1], "slave") == 0) ||
      !argv[2] || !inet_pton(AF_INET6, argv[2], buf)) {
    print_usage();
    return 1;
  }
  if (strcmp(argv[1], "slave") == 0 &&
      (!argv[3] || !inet_pton(AF_INET6, argv[3], buf))) {
    print_usage();
    return 1;
  }
  if (strcmp(argv[1], "slave") == 0) {
    memcpy(nodeip, argv[2], INET6_ADDRSTRLEN - 1);
    memcpy(masterip, argv[3], INET6_ADDRSTRLEN - 1);
    if (argc > 3 && argv[4]) {
      silent = true;
    }
  } else if (strcmp(argv[1], "master") == 0) {
    memcpy(nodeip, argv[2], INET6_ADDRSTRLEN - 1);
    memcpy(masterip, argv[2], INET6_ADDRSTRLEN - 1);
    if (argc > 2 && argv[3]) {
      silent = true;
    }
  }

  FILE* fp;
  struct stat st;
  if (stat("./log", &st) == -1) {
    mkdir("./log", 0700);
  }
  char* fname = malloc(strlen("./log/chord.log") + sizeof(pid_t) + 4);
  sprintf(fname, "./log/chord.%d.log", getpid());
  fp = fopen(fname, "w");
  if (!fp) {
    perror("open state");
    exit(0);
  }

  char* log_fname = malloc(strlen("/tmp/chord_out.log") + 6);
  memset(log_fname, 0, strlen("/tmp/chord_out.log") + 6);
  sprintf(log_fname, "/tmp/chord_out.%d.log", getpid());
#ifdef DEBUG_ENABLE
  default_out = fopen(log_fname, "w");
  if (!default_out) {
    perror("open stdout log");
    exit(0);
  }
#endif

  if (init_chord(nodeip) == CHORD_ERR) {
    return -1;
  }
  struct node* mynode = get_own_node();
  if (!silent)
    printf("nodekey for %s is: %d\n", nodeip, mynode->id);

  if (strcmp(nodeip, masterip) == 0) {
    if (!silent)
      printf("Create new ring\n");
    add_node(NULL);
  } else {
    if (!silent)
      printf("no master node here connect to %s\n", masterip);
    create_node(masterip, partner);
    add_node(partner);
  }
  if (!silent)
    printf("create eventloop thread\n");
  pthread_create(&mythread1, NULL, thread_wait_for_msg, (void*)mynode);
  if (!silent)
    printf("create periodic thread\n");
  pthread_create(&mythread2, NULL, thread_periodic, (void*)mynode);

  signal(SIGINT, sig_handler);
  while (!sigint) {
    struct node* node = get_own_node();
    if (!node_is_null(node->predecessor)) {
      if (node->successor) {
        fprintf(fp,
                "%d|%d|%d\n",
                node->predecessor->id,
                node->id,
                node->successor->id);
      } else {
        fprintf(fp, "%d|%d|NULL\n", node->predecessor->id, node->id);
      }
    } else {
      if (node->successor) {
        fprintf(fp, "NULL|%d|%d\n", node->id, node->successor->id);
      } else {
        fprintf(fp, "NULL|%d|NULL\n", node->id);
      }
    }
    fflush(fp);
    sleep(1);
  }
  free(partner);
  printf("wait for eventloop thread\n");
  if (pthread_cancel(mythread1) != 0) {
    printf("Error cancel thread 1\n");
  }
  if (pthread_cancel(mythread2) != 0) {
    printf("Error cancel thread 2s\n");
  }
  printf("FINAL: ");
#ifdef DEBUG_ENABLE
  debug_print_node(mynode, false);
#endif
  fflush(stdout);
  pthread_join(mythread1, NULL);
  pthread_join(mythread2, NULL);
}
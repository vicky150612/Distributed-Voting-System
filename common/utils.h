#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>

extern char server_region[4];

#define SECRET "__KiHsn&7dd*8"
#define EXPIRY 300
#define KEY_REQ 1234
#define KEY_RES 5678
#define MAX_SERVERS 3
#define MAX_REGIONS 3
#define SHM_RESULT_KEY 10000
#define MAX_CANDIDATES 26

struct msg
{
    long type;
    int sender_pid;
    char cmd[20];
    char voter_id[20];
    char candidate;
    int status;
    char region[4];
};

typedef struct
{
    pid_t server_pid;
    char region[4];
    int ready;
    int total_votes;
    int counts[MAX_CANDIDATES];
} result_entry;

typedef struct
{
    int server_count;
    result_entry entries[MAX_SERVERS];
} result_shm;

void lock_file(int fd);
void read_lock_file(int fd);
void unlock_file(int fd);
unsigned long hash(char *str);

#endif
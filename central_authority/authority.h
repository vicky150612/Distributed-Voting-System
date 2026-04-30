#ifndef AUTHORITY_H
#define AUTHORITY_H

#include <sys/types.h>
#include <fcntl.h>

#define SHM_KEY 9999

// Correct password: "admin123"
#define CORRECT_PASSWORD_HASH 7572152304808164

typedef struct
{
    pid_t pid;
    char region[4];
    int connected;
} server_info;

static server_info *servers;
static int *server_count_ptr;
static volatile int keep_running = 1;
static int req_q, res_q;

int authority();

#endif

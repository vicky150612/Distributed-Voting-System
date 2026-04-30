#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include "../common/utils.h"
#include "auth.h"
#include "vote.h"
#include "server.h"

#define BASE_PORT 8080

char server_region[4] = "";

static volatile sig_atomic_t voteflag = 0; // sig_atomic_t means that it guarantees atomic when a signal interrupts.
static pthread_mutex_t voteflag_mutex = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t server_running = 1;

int get_voteflag(void)
{
    pthread_mutex_lock(&voteflag_mutex);
    int v = voteflag;
    pthread_mutex_unlock(&voteflag_mutex);
    return v;
}

void set_voteflag(int v)
{
    pthread_mutex_lock(&voteflag_mutex);
    voteflag = (sig_atomic_t)v;
    pthread_mutex_unlock(&voteflag_mutex);
}

static void start_voting_handler()
{
    set_voteflag(1);
    printf("Voting enabled (SIGUSR1 received)\n");
}

static void stop_voting_handler()
{
    set_voteflag(0);
    printf("Voting disabled (SIGUSR2 received)\n");
}

static void stop_running()
{
    server_running = 0;
    printf("Authority has exited - shutting down server\n");
    _exit(0);
}

static void run_admin_session(int client_fd)
{
    char buffer[256];

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        int n = read(client_fd, buffer, sizeof(buffer) - 1);
        if (n <= 0)
        {
            break;
        }
        buffer[n] = '\0';

        if (strncmp(buffer, "ADMIN_ENABLE", 12) == 0)
        {
            set_voteflag(1);
            printf("[Admin] Voting ENABLED for region %s\n", server_region);
            write(client_fd, "OK: voting enabled", 18);
        }
        else if (strncmp(buffer, "ADMIN_DISABLE", 13) == 0)
        {
            set_voteflag(0);
            printf("[Admin] Voting DISABLED for region %s\n", server_region);
            write(client_fd, "OK: voting disabled", 19);
        }
        else if (strncmp(buffer, "ADMIN_VERIFY", 12) == 0)
        {
            int result = verify_audit();
            if (result == 1)
            {
                write(client_fd, "VERIFY_OK", 9);
            }
            else if (result == -1)
            {
                write(client_fd, "VERIFY_FAIL: audit log missing", 30);
            }
            else if (result == -2)
            {
                write(client_fd, "VERIFY_FAIL: entry number mismatch", 34);
            }
            else if (result == -3)
            {
                write(client_fd, "VERIFY_FAIL: hash chain broken", 30);
            }
            else if (result == -4)
            {
                write(client_fd, "VERIFY_FAIL: data tampered", 26);
            }
            else
            {
                write(client_fd, "VERIFY_FAIL: unknown error", 26);
            }
        }
        else if (strncmp(buffer, "ADMIN_EXIT", 10) == 0)
        {
            write(client_fd, "BYE", 3);
            printf("[Admin] Session ended for region %s\n", server_region);
            break;
        }
        else
        {
            write(client_fd, "UNKNOWN_CMD", 11);
        }
    }
}

static void *handle_client(void *arg)
{
    int client_fd = *(int *)arg;
    free(arg);

    char buffer[256];

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        int n = read(client_fd, buffer, sizeof(buffer) - 1);
        if (n <= 0)
        {
            break;
        }
        buffer[n] = '\0';

        if (strncmp(buffer, "LOGIN", 5) == 0)
        {
            char voter_id[20];
            sscanf(buffer, "LOGIN %19s", voter_id);

            char token[100];
            if (login(voter_id, token))
            {
                write(client_fd, token, strlen(token) + 1);
            }
            else
            {
                write(client_fd, "INVALID VOTER", 14);
            }
        }
        else if (strncmp(buffer, "VOTE", 4) == 0)
        {
            char token[100];
            char candidate;
            sscanf(buffer, "VOTE %99s %c", token, &candidate);

            if (vote(token, candidate))
            {
                write(client_fd, "SUCCESS", 8);
            }
            else
            {
                write(client_fd, "FAILURE", 8);
            }
        }
        else if (strncmp(buffer, "ADMIN_AUTH", 10) == 0)
        {
            unsigned long pw_hash = 0;
            sscanf(buffer, "ADMIN_AUTH %lu", &pw_hash);

            if (is_valid_admin_password(pw_hash))
            {
                write(client_fd, "ADMIN_OK", 8);
                printf("[Admin] Authenticated on region %s\n", server_region);
                run_admin_session(client_fd);
                break;
            }
            else
            {
                write(client_fd, "ADMIN_FAIL", 10);
                printf("[Admin] Failed authentication attempt on region %s\n", server_region);
            }
        }
    }

    close(client_fd);
    return NULL;
}

// Initial connection with authority.
static int connect_to_authority(void)
{
    int req_q = msgget(KEY_REQ, 0666);
    int res_q = msgget(KEY_RES, 0666);

    if (req_q < 0 || res_q < 0)
    {
        return -1;
    }

    struct msg connect_msg;
    memset(&connect_msg, 0, sizeof(connect_msg));
    connect_msg.type = 1;
    connect_msg.sender_pid = getpid();
    strcpy(connect_msg.cmd, "CONNECT");
    strcpy(connect_msg.region, server_region);

    if (msgsnd(req_q, &connect_msg, sizeof(connect_msg) - sizeof(long), 0) == -1)
    {
        return -1;
    }

    if (msgrcv(res_q, &connect_msg, sizeof(connect_msg) - sizeof(long), getpid(), 0) == -1)
    {
        return -1;
    }

    return connect_msg.status;
}

// Writes results from tally.txt file to SHM.
static void write_results_to_shm(void)
{
    int shmid = shmget(SHM_RESULT_KEY, sizeof(result_shm), 0666);
    if (shmid < 0)
    {
        return;
    }

    result_shm *shm = (result_shm *)shmat(shmid, NULL, 0);
    if (shm == (result_shm *)-1)
    {
        return;
    }

    result_entry *entry = NULL;
    for (int i = 0; i < shm->server_count; i++)
    {
        if (shm->entries[i].server_pid == getpid())
        {
            entry = &shm->entries[i];
            break;
        }
    }

    if (!entry)
    {
        fprintf(stderr, "Server %d: no pre-allocated SHM slot\n", getpid());
        shmdt(shm);
        return;
    }

    strcpy(entry->region, server_region);

    char tally_path[256];
    snprintf(tally_path, sizeof(tally_path), "regional_server/data/%s/tally.txt", server_region);

    int fd = open(tally_path, O_RDONLY);
    if (fd < 0)
    {
        entry->ready = -1;
        shmdt(shm);
        return;
    }

    read_lock_file(fd);
    FILE *fp = fdopen(fd, "r");
    if (!fp)
    {
        unlock_file(fd);
        close(fd);
        entry->ready = -1;
        shmdt(shm);
        return;
    }

    memset(entry->counts, 0, sizeof(entry->counts));
    entry->total_votes = 0;

    char line[32];
    while (fgets(line, sizeof(line), fp))
    {
        char candidate;
        int count;
        if (sscanf(line, "%c %d", &candidate, &count) == 2)
        {
            if (candidate >= 'A' && candidate < 'Z')
            {
                int idx = candidate - 'A';
                entry->counts[idx] = count;
                entry->total_votes += count;
            }
        }
    }
    unlock_file(fd);
    fclose(fp);
    entry->ready = 1;
    shmdt(shm);
}

// Listen to authority actions and take appropriate actions.
static void *listen_authority(void *arg)
{
    (void)arg;
    int req_q = msgget(KEY_REQ, 0666);
    int res_q = msgget(KEY_RES, 0666);

    while (1)
    {
        struct msg msg;
        memset(&msg, 0, sizeof(msg));
        if (msgrcv(req_q, &msg, sizeof(msg) - sizeof(long), getpid(), 0) > 0)
        {
            if (strcmp(msg.cmd, "VERIFY") == 0)
            {
                int x = verify_audit();
                msg.status = x;
                msg.sender_pid = getpid();
                msg.type = 1;
                msgsnd(res_q, &msg, sizeof(msg) - sizeof(long), 0);
            }
            else if (strcmp(msg.cmd, "RESULTS") == 0)
            {
                int reply_to = msg.sender_pid;
                write_results_to_shm();
                msg.status = 1;
                msg.sender_pid = getpid();
                msg.type = reply_to;
                msgsnd(res_q, &msg, sizeof(msg) - sizeof(long), 0);
            }
        }
    }
    return NULL;
}

// When server starts check and create region specific files.
static void init_region_files(const char *region)
{
    char data_base[200];
    snprintf(data_base, sizeof(data_base), "regional_server/data");

    struct stat st;
    if (stat(data_base, &st) == -1)
    {
        mkdir(data_base, 0755);
    }

    char data_dir[200];
    snprintf(data_dir, sizeof(data_dir), "regional_server/data/%s", region);

    if (stat(data_dir, &st) == -1)
    {
        mkdir(data_dir, 0755);
    }

    char voters_path[256];
    snprintf(voters_path, sizeof(voters_path), "%s/voterlist.txt", data_dir);
    FILE *fp = fopen(voters_path, "r");
    if (!fp)
    {
        fp = fopen(voters_path, "w");
        if (fp)
        {
            for (int i = 101; i <= 140; i++)
            {
                fprintf(fp, "%d\n", i);
            }
            fclose(fp);
        }
    }
    else
    {
        fclose(fp);
    }

    char tally_path[256];
    snprintf(tally_path, sizeof(tally_path), "%s/tally.txt", data_dir);
    fp = fopen(tally_path, "r");
    if (!fp)
    {
        fp = fopen(tally_path, "w");
        if (fp)
        {
            fclose(fp);
        }
    }
    else
    {
        fclose(fp);
    }

    char voted_path[256];
    snprintf(voted_path, sizeof(voted_path), "%s/voted.txt", data_dir);
    fp = fopen(voted_path, "a");
    if (fp)
    {
        fclose(fp);
    }

    char audit_path[256];
    snprintf(audit_path, sizeof(audit_path), "%s/audit.log", data_dir);
    fp = fopen(audit_path, "a");
    if (fp)
    {
        fclose(fp);
    }
}
int main()
{
    printf("Select region (R1, R2, or R3): ");
    fflush(stdout);
    scanf("%s", server_region);

    int port = BASE_PORT;
    if (strcmp(server_region, "R1") == 0)
    {
        port = BASE_PORT;
    }
    else if (strcmp(server_region, "R2") == 0)
    {
        port = BASE_PORT + 1;
    }
    else if (strcmp(server_region, "R3") == 0)
    {
        port = BASE_PORT + 2;
    }
    else
    {
        printf("Invalid region. Use R1, R2, or R3.\n");
        return 1;
    }

    init_region_files(server_region);

    int conn_status = connect_to_authority();
    if (conn_status != 1)
    {
        if (conn_status == -1)
        {
            printf("Connection rejected\n");
        }
        else
        {
            printf("Could not connect to central authority.\n");
        }
        return 1;
    }

    printf("Voting is initially disabled\n");

    pthread_t auth_thread;
    pthread_create(&auth_thread, NULL, listen_authority, NULL);
    pthread_detach(auth_thread);

    signal(SIGUSR1, start_voting_handler);
    signal(SIGUSR2, stop_voting_handler);
    signal(SIGTERM, stop_running);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0)
    {
        close(server_fd);
        return 1;
    }

    printf("Region %s server listening on port %d\n", server_region, port);

    while (server_running)
    {
        int *client_fd = malloc(sizeof(int));
        if (!client_fd)
        {
            continue;
        }

        *client_fd = accept(server_fd, NULL, NULL);
        if (*client_fd < 0)
        {
            free(client_fd);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client_fd);
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}

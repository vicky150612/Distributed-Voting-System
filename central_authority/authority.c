#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include "../common/utils.h"
#include "authority.h"

// Checks if a user has voted and if not, adds the vote.
static int vote_global(char *voter_id)
{
    FILE *fp = fopen("central_authority/voted_global.txt", "a+");
    if (!fp)
    {
        return 1;
    }

    int fd = fileno(fp);
    lock_file(fd);
    rewind(fp);

    char line[50];
    while (fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, voter_id) == 0)
        {
            unlock_file(fd);
            fclose(fp);
            return 1;
        }
    }

    fprintf(fp, "%s\n", voter_id);
    fflush(fp);
    unlock_file(fd);
    fclose(fp);
    return 0;
}

// Registers server (i.e stores server pid for future references.)
static int register_server(pid_t server_pid, const char *region)
{
    for (int i = 0; i < *server_count_ptr; i++)
    {
        if (servers[i].connected && strcmp(servers[i].region, region) == 0)
        {
            return -1;
        }
    }

    for (int i = 0; i < *server_count_ptr; i++)
    {
        if (servers[i].pid == server_pid)
        {
            servers[i].connected = 1;
            return 1;
        }
    }

    if (*server_count_ptr >= MAX_SERVERS)
    {
        return -1;
    }

    servers[*server_count_ptr].pid = server_pid;
    strncpy(servers[*server_count_ptr].region, region, sizeof(servers[0].region) - 1);
    servers[*server_count_ptr].connected = 1;
    (*server_count_ptr)++;
    return 1;
}

// Sends a signal to all servers.
static void send_signal_to_all_servers(int signum)
{
    int sent = 0;
    for (int i = 0; i < *server_count_ptr; i++)
    {
        if (servers[i].connected && kill(servers[i].pid, signum) == 0)
        {
            sent++;
        }
    }

    if (signum == SIGUSR1)
    {
        printf("Voting enabled  for %d region(s)\n", sent);
    }
    else if (signum == SIGUSR2)
    {
        printf("Voting disabled for %d region(s)\n", sent);
    }
}

// sends a signal to a specific region.
static void send_signal_to_region(const char *region, int signum)
{
    int found = 0;
    for (int i = 0; i < *server_count_ptr; i++)
    {
        if (servers[i].connected && strcmp(servers[i].region, region) == 0)
        {
            if (kill(servers[i].pid, signum) == 0)
            {
                found = 1;
                if (signum == SIGUSR1)
                {
                    printf("Voting enabled  for region %s\n", region);
                }
                else if (signum == SIGUSR2)
                {
                    printf("Voting disabled for region %s\n", region);
                }
            }
        }
    }
    if (!found)
    {
        printf("No active server found for region %s\n", region);
    }
}

// Sends a verification order to all servers.
static void verify_servers()
{
    if (*server_count_ptr == 0)
    {
        printf("No connected servers.\n");
        return;
    }

    printf("Verifying servers...\n");
    for (int i = 0; i < *server_count_ptr; i++)
    {
        if (!servers[i].connected)
        {
            continue;
        }

        struct msg verify_msg;
        memset(&verify_msg, 0, sizeof(verify_msg));
        verify_msg.type = servers[i].pid;
        verify_msg.sender_pid = 1;
        strcpy(verify_msg.cmd, "VERIFY");

        if (msgsnd(req_q, &verify_msg, sizeof(verify_msg) - sizeof(long), 0) == -1)
        {
            continue;
        }

        if (msgrcv(res_q, &verify_msg, sizeof(verify_msg) - sizeof(long), 1, 0) == -1)
        {
            continue;
        }

        pid_t responder = verify_msg.sender_pid;
        int idx = -1;
        for (int j = 0; j < *server_count_ptr; j++)
        {
            if (servers[j].pid == responder)
            {
                idx = j;
                break;
            }
        }

        const char *reg = servers[idx].region;
        int s = verify_msg.status;
        if (s == 1)
        {
            printf("Region %s: audit verified successfully\n", reg);
        }
        else if (s == -1)
        {
            printf("Region %s: audit log missing\n", reg);
        }
        else if (s == -2)
        {
            printf("Region %s: entry number mismatch\n", reg);
        }
        else if (s == -3)
        {
            printf("Region %s: hash chain broken\n", reg);
        }
        else if (s == -4)
        {
            printf("Region %s: data tampered\n", reg);
        }
        else
        {
            printf("Region %s: unknown error (%d)\n", reg, s);
        }
    }
    printf("Verification complete.\n");
}

// Count all global votes.
static int count_global_votes()
{
    int fd = open("central_authority/voted_global.txt", O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }

    read_lock_file(fd);

    FILE *fp = fdopen(fd, "r");
    if (!fp)
    {
        unlock_file(fd);
        close(fd);
        {
            return -1;
        }
    }

    int count = 0;
    char line[50];
    while (fgets(line, sizeof(line), fp))
    {
        count++;
    }

    unlock_file(fd);
    fclose(fp);
    return count;
}

// Collect results from all servers, includes few steps:
// 1) Disable voting for all servers.
// 2) Create a shared memory for servers to write data to.
// 3) Send result collection order to all servers.
// 4) aggregates total results and verify with global count.
static void collect_results()
{
    if (*server_count_ptr == 0)
    {
        printf("No connected servers.\n");
        return;
    }

    printf("Disabling voting and collecting results...\n");
    send_signal_to_all_servers(SIGUSR2);
    usleep(500000);

    int shmid = shmget(SHM_RESULT_KEY, sizeof(result_shm), 0666 | IPC_CREAT);
    if (shmid < 0)
    {
        return;
    }

    result_shm *shm = (result_shm *)shmat(shmid, NULL, 0);
    if (shm == (result_shm *)-1)
    {
        shmctl(shmid, IPC_RMID, NULL);
        return;
    }

    memset(shm, 0, sizeof(result_shm));
    shm->server_count = *server_count_ptr;
    for (int i = 0; i < *server_count_ptr; i++)
    {
        shm->entries[i].server_pid = servers[i].pid;
        strncpy(shm->entries[i].region, servers[i].region, sizeof(shm->entries[i].region) - 1);
        shm->entries[i].ready = 0;
    }

    for (int i = 0; i < *server_count_ptr; i++)
    {
        struct msg req;
        memset(&req, 0, sizeof(req));
        req.type = servers[i].pid;
        req.sender_pid = 1;
        strcpy(req.cmd, "RESULTS");
        msgsnd(req_q, &req, sizeof(req) - sizeof(long), 0);
    }

    int attempts = 0, all_ready = 0;
    while (attempts < 50)
    {
        all_ready = 1;
        for (int i = 0; i < shm->server_count; i++)
        {
            if (shm->entries[i].server_pid != 0 &&
                shm->entries[i].ready == 0)
            {
                all_ready = 0;
                break;
            }
        }
        if (all_ready)
        {
            break;
        }
        usleep(100000);
        attempts++;
    }

    if (!all_ready)
    {
        printf("Warning: not all regions responded in time.\n");
    }

    int aggregate[MAX_CANDIDATES] = {0};
    int total_votes = 0, responded = 0;

    for (int i = 0; i < shm->server_count; i++)
    {
        const char *reg = shm->entries[i].region;
        if (shm->entries[i].server_pid == 0)
        {
            continue;
        }

        if (shm->entries[i].ready == 1)
        {
            responded++;
            for (int c = 0; c < MAX_CANDIDATES; c++)
            {
                aggregate[c] += shm->entries[i].counts[c];
            }
            total_votes += shm->entries[i].total_votes;
        }
        else if (shm->entries[i].ready == -1)
        {
            printf("Region %s: error reading tally\n", reg);
        }
        else
        {
            printf("Region %s: did not respond\n", reg);
        }
    }

    printf("\n=== RESULTS ===\n");
    printf("Regions responded: %d/%d\n", responded, shm->server_count);
    for (int c = 0; c < MAX_CANDIDATES; c++)
    {
        if (aggregate[c] > 0)
        {
            printf("  %c: %d\n", 'A' + c, aggregate[c]);
        }
    }
    printf("Total votes cast: %d\n", total_votes);

    int global = count_global_votes();
    if (global >= 0)
    {
        printf("Global unique voters: %d\n", global);
        if (global == total_votes)
        {
            printf("Integrity check PASSED\n");
        }
        else
        {
            printf("Integrity check FAILED: global %d != aggregated %d\n", global, total_votes);
        }
    }

    shmdt(shm);
    shmctl(shmid, IPC_RMID, NULL);
}

static void handle_user_input()
{
    int choice;

    while (1)
    {
        printf("\n1. Enable  voting (all regions)\n");
        printf("2. Disable voting (all regions)\n");
        printf("3. Enable  voting (specific region)\n");
        printf("4. Disable voting (specific region)\n");
        printf("5. Verify  servers\n");
        printf("6. Results\n");
        printf("7. Exit\n");
        printf("Choice: ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1)
        {
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            continue;
        }

        if (choice == 1)
        {
            send_signal_to_all_servers(SIGUSR1);
        }
        else if (choice == 2)
        {
            send_signal_to_all_servers(SIGUSR2);
        }
        else if (choice == 3)
        {
            printf("Enter region (R1, R2, R3): ");
            char region[4];
            scanf("%3s", region);
            send_signal_to_region(region, SIGUSR1);
        }
        else if (choice == 4)
        {
            printf("Enter region (R1, R2, R3): ");
            char region[4];
            scanf("%3s", region);
            send_signal_to_region(region, SIGUSR2);
        }
        else if (choice == 5)
        {
            verify_servers();
        }
        else if (choice == 6)
        {
            collect_results();
        }
        else if (choice == 7)
        {
            printf("Shutting down all region servers...\n");
            send_signal_to_all_servers(SIGTERM);
            printf("Exiting authority.\n");
            break;
        }
        else
        {
            printf("Invalid choice.\n");
        }
    }
}

int main()
{
    char input_password[100];
    printf("=== Central Authority Authentication ===\n");
    printf("Enter password: ");
    fflush(stdout);

    if (fgets(input_password, sizeof(input_password), stdin) == NULL)
    {
        printf("Authentication failed.\n");
        exit(1);
    }
    input_password[strcspn(input_password, "\n")] = '\0';

    if (hash(input_password) != CORRECT_PASSWORD_HASH)
    {
        printf("Authentication failed. Incorrect password.\n");
        exit(1);
    }
    printf("Authentication successful!\n\n");

    req_q = msgget(KEY_REQ, 0666 | IPC_CREAT);
    res_q = msgget(KEY_RES, 0666 | IPC_CREAT);
    if (req_q < 0 || res_q < 0)
    {
        exit(1);
    }

    int shmid = shmget(SHM_KEY, sizeof(server_info) * MAX_SERVERS + sizeof(int), 0666 | IPC_CREAT);
    if (shmid < 0)
    {
        exit(1);
    }

    servers = (server_info *)shmat(shmid, NULL, 0);
    if (servers == (server_info *)-1)
    {
        exit(1);
    }

    server_count_ptr = (int *)(servers + MAX_SERVERS);
    *server_count_ptr = 0;

    pid_t child_pid = fork();
    if (child_pid < 0)
    {
        exit(1);
    }

    if (child_pid == 0)
    {
        handle_user_input();
        exit(0);
    }

    struct msg message;
    while (1)
    {
        int status;
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        if (result == child_pid)
        {
            printf("User input handler exited. Shutting down authority...\n");
            break;
        }

        if (msgrcv(req_q, &message, sizeof(message) - sizeof(long), 1, IPC_NOWAIT) > 0)
        {
            if (strcmp(message.cmd, "CONNECT") == 0)
            {
                int reg_status = register_server(message.sender_pid, message.region);
                message.status = reg_status;
                message.type = message.sender_pid;
                msgsnd(res_q, &message, sizeof(message) - sizeof(long), 0);
            }
            else if (strcmp(message.cmd, "CHECK") == 0)
            {
                message.status = vote_global(message.voter_id) ? 0 : 1;
                message.type = message.sender_pid;
                msgsnd(res_q, &message, sizeof(message) - sizeof(long), 0);
            }
        }

        usleep(10000);
    }

    msgctl(req_q, IPC_RMID, NULL);
    msgctl(res_q, IPC_RMID, NULL);
    shmdt(servers);
    shmctl(shmid, IPC_RMID, NULL);

    printf("Central Authority stopped.\n");
    return 0;
}

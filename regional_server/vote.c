#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "../common/utils.h"
#include "auth.h"
#include "vote.h"
#include "server.h"

// Update tally by incrementing vote for the specific candidate.
static int update_tally(char candidate)
{
    char tally_path[256];
    snprintf(tally_path, sizeof(tally_path), "regional_server/data/%s/tally.txt", server_region);

    FILE *fp = fopen(tally_path, "r+");
    if (!fp)
    {
        return 0;
    }

    int fd = fileno(fp);
    lock_file(fd);
    rewind(fp);

    char line[20];
    long found_pos = -1;
    int current_votes = 0;
    long pos;

    while (1)
    {
        pos = ftell(fp);
        if (!fgets(line, sizeof(line), fp))
        {
            break;
        }
        if (line[0] == candidate)
        {
            found_pos = pos;
            sscanf(line + 2, "%08d", &current_votes);
            break;
        }
    }

    if (found_pos != -1)
    {
        fseek(fp, found_pos, SEEK_SET);
        fprintf(fp, "%c %08d\n", candidate, current_votes + 1);
    }
    else
    {
        fseek(fp, 0, SEEK_END);
        fprintf(fp, "%c %08d\n", candidate, 1);
    }

    fflush(fp);
    unlock_file(fd);
    fclose(fp);
    return 1;
}

// When new vote is added, update audit file accordingly.
static void append_audit(char *voter_id, char candidate)
{
    char audit_path[256];
    snprintf(audit_path, sizeof(audit_path), "regional_server/data/%s/audit.log", server_region);

    FILE *fp = fopen(audit_path, "r+");
    if (!fp)
    {
        fp = fopen(audit_path, "w+");
    }
    if (!fp)
    {
        return;
    }

    int fd = fileno(fp);
    lock_file(fd);
    rewind(fp);

    char line[200];
    char last_hash[50] = "0";
    int entry_no = 0;

    while (fgets(line, sizeof(line), fp))
    {
        sscanf(line, "%d | %*s | %*s | %*c | %49s", &entry_no, last_hash);
    }

    entry_no++;

    char data[200];
    sprintf(data, "%s%s%c", last_hash, voter_id, candidate);
    unsigned long curr_hash = hash(data);

    fseek(fp, 0, SEEK_END);
    fprintf(fp, "%d | %s | %s | %c | %lu\n", entry_no, last_hash, voter_id, candidate, curr_hash);

    fflush(fp);
    unlock_file(fd);
    fclose(fp);
}

// Verify if audit file is valid.
int verify_audit(void)
{
    char audit_path[256];
    snprintf(audit_path, sizeof(audit_path), "regional_server/data/%s/audit.log", server_region);

    int fd = open(audit_path, O_RDONLY);
    if (fd < 0)
    {
        printf("Audit log not found\n");
        return -1;
    }

    read_lock_file(fd);

    FILE *fp = fdopen(fd, "r");
    if (!fp)
    {
        unlock_file(fd);
        close(fd);
        return -1;
    }

    char line[256];
    char prev_hash[50] = "0";
    int expected_entry = 1;
    int result = 1;

    while (fgets(line, sizeof(line), fp))
    {
        int entry_no;
        char stored_prev[50], voter_id[20];
        char candidate;
        unsigned long stored_hash;

        if (sscanf(line, "%d | %49s | %19s | %c | %lu", &entry_no, stored_prev, voter_id, &candidate, &stored_hash) != 5)
        {
            continue;
        }

        if (entry_no != expected_entry)
        {
            printf("Entry number mismatch at %d\n", entry_no);
            result = -2;
            break;
        }
        if (strcmp(stored_prev, prev_hash) != 0)
        {
            printf("Hash chain broken at entry %d\n", entry_no);
            result = -3;
            break;
        }

        char data[200];
        sprintf(data, "%s%s%c", stored_prev, voter_id, candidate);
        if (hash(data) != stored_hash)
        {
            printf("Data tampered at entry %d\n", entry_no);
            result = -4;
            break;
        }

        snprintf(prev_hash, sizeof(prev_hash), "%lu", stored_hash);
        expected_entry++;
    }

    unlock_file(fd);
    fclose(fp);

    if (result == 1)
    {
        printf("Audit log verified successfully\n");
    }
    return result;
}

// Check if the user has voted globally.
static int check_with_authority(char *voter_id)
{
    struct msg message;
    memset(&message, 0, sizeof(message));

    int req_q = msgget(KEY_REQ, 0666);
    int res_q = msgget(KEY_RES, 0666);

    message.type = 1;
    message.sender_pid = getpid();
    strcpy(message.cmd, "CHECK");
    strcpy(message.voter_id, voter_id);

    msgsnd(req_q, &message, sizeof(message) - sizeof(long), 0);
    msgrcv(res_q, &message, sizeof(message) - sizeof(long), getpid(), 0);

    return message.status;
}

int vote(char *token, char candidate)
{
    if (!get_voteflag())
    {
        printf("Vote rejected: voting is currently disabled\n");
        return 0;
    }

    if (!validate_token(token))
    {
        return 0;
    }

    char voter_id[20];
    getvoterid(token, voter_id);

    char voted_path[256];
    snprintf(voted_path, sizeof(voted_path), "regional_server/data/%s/voted.txt", server_region);

    FILE *fp = fopen(voted_path, "a+");
    if (!fp)
    {
        return 0;
    }

    int fd = fileno(fp);
    lock_file(fd);
    rewind(fp);

    char line[20];
    while (fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, voter_id) == 0)
        {
            unlock_file(fd);
            fclose(fp);
            return 0;
        }
    }

    fprintf(fp, "%s\n", voter_id);
    fflush(fp);
    unlock_file(fd);
    fclose(fp);

    if (!check_with_authority(voter_id))
    {
        return 0;
    }

    update_tally(candidate);
    append_audit(voter_id, candidate);

    printf("Received vote: %c\n", candidate);
    return 1;
}

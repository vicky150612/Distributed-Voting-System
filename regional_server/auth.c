#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "../common/utils.h"
#include "auth.h"

/*
 * Per-region admin password hashes.
 *   R1 → "AdminR1"
 *   R2 → "AdminR2"
 *   R3 → "AdminR3"
 */
#define ADMIN_HASH_R1 229417833777841
#define ADMIN_HASH_R2 229417833777842
#define ADMIN_HASH_R3 229417833777843

// Generates a token for sending to client.
void generate_token(char *voter_id, char *token)
{
    long timestamp = time(NULL);

    char data[100];
    sprintf(data, "%s%ld%s", voter_id, timestamp, SECRET);

    unsigned long sig = hash(data);
    sprintf(token, "%s.%ld.%lu", voter_id, timestamp, sig);
}

// Verifies if the token sent by client is correct.
int validate_token(char *token)
{
    char voter_id[20];
    long timestamp;
    unsigned long sig;

    sscanf(token, "%[^.].%ld.%lu", voter_id, &timestamp, &sig);

    char data[100];
    sprintf(data, "%s%ld%s", voter_id, timestamp, SECRET);

    if (hash(data) != sig)
    {
        return 0;
    }

    if (time(NULL) - timestamp > EXPIRY)
    {
        return 0;
    }

    return 1;
}

// Extracts voterid from toke.
void getvoterid(char *token, char *voter_id)
{
    sscanf(token, "%[^.]", voter_id);
}

// Checks if voter is valid.
int is_valid_voter(char *voter_id)
{
    char voterlist_path[256];
    snprintf(voterlist_path, sizeof(voterlist_path), "regional_server/data/%s/voterlist.txt", server_region);

    int fd = open(voterlist_path, O_RDONLY);
    if (fd < 0)
        return 0;

    read_lock_file(fd);

    FILE *fp = fdopen(fd, "r");
    if (!fp)
    {
        unlock_file(fd);
        close(fd);
        return 0;
    }

    char line[20];
    int found = 0;
    while (fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, voter_id) == 0)
        {
            found = 1;
            break;
        }
    }

    unlock_file(fd);
    fclose(fp);
    return found;
}

int login(char *voter_id, char *token)
{
    if (!is_valid_voter(voter_id))
    {
        return 0;
    }
    generate_token(voter_id, token);
    return 1;
}

// Check admin password
int is_valid_admin_password(unsigned long password_hash)
{
    if (strcmp(server_region, "R1") == 0)
    {
        return password_hash == ADMIN_HASH_R1;
    }
    if (strcmp(server_region, "R2") == 0)
    {
        return password_hash == ADMIN_HASH_R2;
    }
    if (strcmp(server_region, "R3") == 0)
    {
        return password_hash == ADMIN_HASH_R3;
    }
    return 0;
}
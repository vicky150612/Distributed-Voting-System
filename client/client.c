#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <arpa/inet.h>
#include "../common/utils.h"
#include "client.h"

#define SERVER_IP "127.0.0.1"
#define BASE_PORT 8080

static int region_to_port(const char *region)
{
    if (strcmp(region, "R1") == 0)
    {
        return BASE_PORT;
    }
    if (strcmp(region, "R2") == 0)
    {
        return BASE_PORT + 1;
    }
    if (strcmp(region, "R3") == 0)
    {
        return BASE_PORT + 2;
    }
    return -1;
}

static int connect_to_region(const char *region)
{
    int port = region_to_port(region);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return -1;
    }
    return sock;
}

static int run_admin(const char *region, int sock)
{
    printf("\n=== Admin Login — Region %s ===\n", region);

    char password[128];
    getchar();
    printf("Enter admin password: ");
    fflush(stdout);

    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    unsigned long pw_hash = hash(password);

    char msg[64];
    snprintf(msg, sizeof(msg), "ADMIN_AUTH %lu", pw_hash);
    write(sock, msg, strlen(msg) + 1);

    char resp[64];
    int n = read(sock, resp, sizeof(resp) - 1);
    if (n <= 0)
    {
        printf("Server closed connection.\n");
        close(sock);
        return 1;
    }
    resp[n] = '\0';

    if (strcmp(resp, "ADMIN_OK") != 0)
    {
        printf("Authentication failed. Wrong password.\n");
        close(sock);
        return 1;
    }

    printf("Authenticated as admin for region %s.\n\n", region);

    while (1)
    {
        printf("--- Admin Menu [%s] ---\n", region);
        printf("  1. Enable  voting\n");
        printf("  2. Disable voting\n");
        printf("  3. Verify  audit log\n");
        printf("  4. Exit\n");
        printf("Choice: ");
        fflush(stdout);

        int choice;
        if (scanf("%d", &choice) != 1)
        {
            choice = -1;
        }

        const char *cmd = NULL;
        if (choice == 1)
        {
            cmd = "ADMIN_ENABLE";
        }
        else if (choice == 2)
        {
            cmd = "ADMIN_DISABLE";
        }
        else if (choice == 3)
        {
            cmd = "ADMIN_VERIFY";
        }
        else if (choice == 4)
        {
            cmd = "ADMIN_EXIT";
        }
        else
        {
            printf("Invalid choice.\n");
            continue;
        }

        write(sock, cmd, strlen(cmd) + 1);

        memset(resp, 0, sizeof(resp));
        n = read(sock, resp, sizeof(resp) - 1);
        if (n <= 0)
        {
            printf("Server closed connection.\n");
            break;
        }
        resp[n] = '\0';
        printf("Server: %s\n\n", resp);

        if (choice == 4)
        {
            break;
        }
    }

    close(sock);
    return 0;
}

static int run_voter(int sock)
{
    printf("Enter voter ID: ");
    fflush(stdout);
    char voter_id[20];
    scanf("%19s", voter_id);

    char msg[256];
    snprintf(msg, sizeof(msg), "LOGIN %s", voter_id);
    write(sock, msg, strlen(msg) + 1);

    char tokenbuffer[100];
    int n = read(sock, tokenbuffer, sizeof(tokenbuffer) - 1);
    if (n <= 0)
    {
        printf("Server closed connection.\n");
        close(sock);
        return 1;
    }
    tokenbuffer[n] = '\0';

    if (strncmp(tokenbuffer, "INVALID", 7) == 0)
    {
        printf("Login failed: %s\n", tokenbuffer);
        close(sock);
        return 0;
    }

    printf("Token received.\n");

    char candidate;
    printf("Choose your candidate (A-Z): ");
    scanf(" %c", &candidate);
    if (candidate < 'A' || candidate > 'Z')
    {
        printf("Invalid chandidate\n");
        close(sock);
        return 1;
    }

    snprintf(msg, sizeof(msg), "VOTE %s %c", tokenbuffer, candidate);
    write(sock, msg, strlen(msg) + 1);

    char status[32];
    n = read(sock, status, sizeof(status) - 1);
    if (n > 0)
    {
        status[n] = '\0';
        printf("Vote status: %s\n", status);
    }

    close(sock);
    return 0;
}

int main()
{
    printf("Select region (R1, R2, or R3): ");
    fflush(stdout);
    char region[4];
    scanf("%s", region);

    if (region_to_port(region) < 0)
    {
        printf("Invalid region. Use R1, R2, or R3.\n");
        return 1;
    }

    int sock = connect_to_region(region);
    if (sock < 0)
    {
        printf("Connection failed.\n");
        return 1;
    }
    printf("Connected to region %s server.\n", region);

    printf("\nRole:\n  1. Voter\n  2. Admin\nChoice: ");
    fflush(stdout);
    int role;
    if (scanf("%d", &role) != 1)
    {
        role = -1;
    }

    if (role == 1)
    {
        return run_voter(sock);
    }
    else if (role == 2)
    {
        return run_admin(region, sock);
    }
    else
    {
        printf("Invalid choice.\n");
        return 1;
    }
}

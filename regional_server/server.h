#ifndef SERVER_H
#define SERVER_H

/* Start the regional TCP server. Blocks indefinitely. */
int server(void);

/* Thread-safe accessors for the voting-enabled flag. */
int get_voteflag(void);
void set_voteflag(int v);

#endif /* SERVER_H */
#ifndef AUTH_H
#define AUTH_H

void generate_token(char *voter_id, char *token);

int validate_token(char *token);

void getvoterid(char *token, char *voter_id);

int is_valid_voter(char *voter_id);

int login(char *voter_id, char *token);

int is_valid_admin_password(unsigned long password_hash);

#endif
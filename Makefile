CC := gcc
CFLAGS := -Wall -Wextra -g -pthread
INCLUDES := -I. -Iclient -Iregional_server -Icentral_authority -Icommon

BIN_DIR := bin

CLIENT := $(BIN_DIR)/client
SERVER := $(BIN_DIR)/server
AUTHORITY := $(BIN_DIR)/authority

CLIENT_SRC := client/client.c common/utils.c
SERVER_SRC := regional_server/server.c regional_server/auth.c regional_server/vote.c common/utils.c
AUTHORITY_SRC := central_authority/authority.c common/utils.c

CLIENT_OBJ := $(CLIENT_SRC:.c=.o)
SERVER_OBJ := $(SERVER_SRC:.c=.o)
AUTHORITY_OBJ := $(AUTHORITY_SRC:.c=.o)

.PHONY: all clean run-client run-server run-authority

all: $(CLIENT) $(SERVER) $(AUTHORITY)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(CLIENT): $(CLIENT_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(SERVER): $(SERVER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(AUTHORITY): $(AUTHORITY_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(BIN_DIR)
	find . -type f -name "*.o" -delete
	rm -f a.out

run-client: $(CLIENT)
	./$(CLIENT)

run-server: $(SERVER)
	./$(SERVER)

run-authority: $(AUTHORITY)
	./$(AUTHORITY)
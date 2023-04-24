CC          = g++
LD          = g++
CFLAG       = -Wall -I./src
PROG_NAME   = NTbuster
STDFLAG     = -std=c++11

SRC_DIR     = ./src
BUILD_DIR   = ./build
BIN_DIR     = ./bin
SRC_LIST    = $(wildcard $(SRC_DIR)/*.cpp)
OBJ_LIST    = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRC_LIST))

.PHONY: all clean $(PROG_NAME) compile

all: $(PROG_NAME)

compile: $(OBJ_LIST)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CC) -c $(CFLAG) $(STDFLAG) $< -o $@

$(PROG_NAME): compile | $(BIN_DIR)
	$(LD) $(OBJ_LIST) -o $(BIN_DIR)/$(PROG_NAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(BIN_DIR)/$(PROG_NAME) $(BUILD_DIR)/*.o
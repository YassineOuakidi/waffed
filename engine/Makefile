# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinclude -g 

# Directories
SRC_DIR = src
BUILD_DIR = build

# Recursively find all .c files in the src/ directory and its subdirectories
SRCS := $(shell find $(SRC_DIR) -name '*.c')

# Map the source files to object files inside the build/ directory
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Final binary target
TARGET = $(BUILD_DIR)/waf

# Default rule when you just type 'make'
all: $(TARGET)

# Rule to link the object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Rule to compile each .c file into a .o file
# The @mkdir ensures the subdirectories (e.g., build/core, build/net) exist before compiling
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to wipe the build directory
clean:
	rm -rf $(BUILD_DIR)/*

# Tell Make these aren't actual files on the disk
.PHONY: all clean

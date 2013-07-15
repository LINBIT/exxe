#ifndef __PARSE_H
#define __PARSE_H

#include <stdbool.h>

struct input_command {
	char command;
	struct buffer input;
	char **argv;
};

struct output_command {
	char command;
	struct buffer output, error;
	unsigned int status, signal;
};

bool parse_input(struct input_command *command);
bool parse_output(struct output_command *command);
void free_argv(char **argv);

#endif  /* __PARSE_H */

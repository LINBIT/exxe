/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

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

/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

#include "buffer.h"
#include "error.h"
#include "parse.h"

/* Expanded variables are put into the expanded_input buffer; the parser reads
   them from there. */
struct buffer expanded_input;
bool have_expanded_input = false;

static int get(void)
{
	if (have_expanded_input) {
		int c = get_buffer(&expanded_input);
		if (c != EOF)
			return c;
		reset_buffer(&expanded_input);
		have_expanded_input = false;
	}
	return fgetc(stdin);
}

static void unget(int c)
{
	if (c != EOF) {
		if (have_expanded_input)
			unget_buffer(&expanded_input, c);
		else
			ungetc(c, stdin);
	}
}

static bool parse_number(unsigned int *number)
{
	struct buffer buffer;
	int c = get();

	if (!(c >= '0' && c <= '9')) {
		unget(c);
		return false;
	}
	init_buffer(&buffer, 0);
	put_buffer(&buffer, c);
	for(;;) {
		c = get();
		if (!(c >= '0' && c <= '9')) {
			unsigned long l;
			char *end;

			unget(c);
			put_buffer(&buffer, 0);
			l = strtoul(buffer_read_pos(&buffer), &end, 10);
			if (*end || l > INT_MAX)
				fatal("Invalid number '%s'",
				      buffer_read_pos(&buffer));
			*number = l;
			free_buffer(&buffer);
			return true;
		}
		put_buffer(&buffer, c);
	}
}

static void parse_data(struct buffer *buffer)
{
	unsigned int size;
	bool size_defined;
	int c;

	size_defined = parse_number(&size);
	c = get();
	if (c != ' ')
		unget(c);
	if (size_defined) {
		size_t ret;

		grow_buffer(buffer, size);
		ret = fread(buffer_write_pos(buffer), 1, size, stdin);
		if (ret != size) {
			if (ferror(stdin))
				fatal("%s", strerror(errno));
			fatal("Unexpected EOF while reading input");
		}
		buffer_advance_write(buffer, size);
	} else {
		for(;;) {
			c = get();
			if (c == EOF)
				break;
			put_buffer(buffer, c);
			if (c == '\n')
				break;
		}
	}
}

static inline bool isname(char c)
{
	return (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z') ||
	       c == '_';
}

static void expand_variable(struct buffer *name)
{
	char *value;

	put_buffer(name, 0);
	value = getenv(buffer_read_pos(name));
	if (value) {
		size_t size = strlen(value);
		grow_buffer(&expanded_input, size);
		memcpy(buffer_write_pos(&expanded_input), value, size);
		buffer_advance_write(&expanded_input, size);
		have_expanded_input = true;
	}
}

static void parse_dollar(struct buffer *buffer)
{
	struct buffer name;
	int c = get();

	switch(c) {
	case '!': case '?': case '*': case '@': case '-': case '_': case '$':
		fatal("Parameter '$%c' not supported", c);
	case '{':
		init_buffer(&name, 0);
		for(;;) {
			c = get();
			if (c == '}')
				break;
			if (!isname(c))
				fatal("Invalid character '%c' in ${...} substitution", c);
			put_buffer(&name, c);
		}
		expand_variable(&name);
		free_buffer(&name);
		return;
	}
	if (c >= '0' && c <= '9')
		fatal("Parameter '$%c' not supported", c);
	else if (isname(c)) {
		init_buffer(&name, 0);
		do {
			put_buffer(&name, c);
			c = get();
		} while (isname(c));
		unget(c);
		expand_variable(&name);
		free_buffer(&name);
	} else {
		put_buffer(&expanded_input, '$');
		unget(c);
		have_expanded_input = true;
	}
}

static void parse_single_quoted(struct buffer *buffer)
{
	int c = get();

	while (c != EOF && (have_expanded_input || c != '\'')) {
		put_buffer(buffer, c);
		c = get();
	}
	if (c == EOF)
		fatal("Unexpected EOF while looking for matching single quote");
}

static void parse_double_quoted(struct buffer *buffer)
{
	int c = get();

	while (c != EOF && (have_expanded_input || c != '"')) {
		if (have_expanded_input)
			goto escaped;
		switch(c) {
		case '$':
			parse_dollar(buffer);
			break;
		case '\\':
			c = get();
			if (c == '\n')
				break;
			if (c == EOF)
				fatal("Unexpected EOF after backslash");
			/* fall through */
		escaped: default:
			put_buffer(buffer, c);
		}
		c = get();
	}
	if (c == EOF)
		fatal("Unexpected EOF while looking for matching single quote");
}

static bool parse_word(struct buffer *buffer, bool *more)
{
	bool defined = false;
	int c = get();

	while (c == ' ' || c == '\t')
		c = get();
	for(;;) {
		switch(c) {
		case ' ': case '\t':
			*more = true;
			goto out;
		case '\n':
			*more = false;
			goto out;
		}

		if (have_expanded_input)
			goto escaped;

		switch(c) {
		case EOF:
			goto out;
		case '\'':
			defined = true;
			parse_single_quoted(buffer);
			break;
		case '"':
			defined = true;
			parse_double_quoted(buffer);
			break;
		case '\\':
			c = get();
			if (c == EOF)
				fatal("Unexpected EOF after backslash");
			if (c == '\n')
				break;
			goto escaped;
		case '$':
			parse_dollar(buffer);
			break;
		escaped: default:
			defined = true;
			put_buffer(buffer, c);
		}
		c = get();
	}

out:
	put_buffer(buffer, 0);
	return defined;
}

void put_arg(struct command *command, char *arg)
{
	command->argv = xrealloc(command->argv,
		(command->argc + 2) * sizeof(*command->argv));
	command->argv[command->argc++] = arg;
	command->argv[command->argc] = NULL;
}

static void parse_command(struct command *command)
{
	int c = get();

	if (c != ' ')
		unget(c);
	for(;;) {
		struct buffer buffer;
		bool more = false;

		init_buffer(&buffer, 0);
		if (!parse_word(&buffer, &more)) {
			if (command->argc)
				return;
			fatal("Unexpected EOF while looking for a word");
		}
		put_arg(command, steal_buffer(&buffer));
		if (!more)
			return;
	}
}

bool parse_exxe_input(struct exxe_input *input)
{
	int c = get();

	while (c == ' ' || c == '\t' || c == '\n')
		c = get();
	switch(c) {
	case '<':  /* standard input */
		parse_data(&input->input);
		input->what = c;
		return true;
	case '!':  /* command to run */
		parse_command(&input->command);
		input->what = c;
		return true;
	default:
		if (c != EOF)
			fatal("Invalid command '%c'", c);
		return false;
	}
}

static void parse_space(char command)
{
	int c = get();

	if (c != ' ')
		fatal("Space expected in command '%c'", c);
}

static void parse_reason(char **reason)
{
	struct buffer buffer;
	int c = get();

	if (c != ' ') {
		unget(c);
		*reason = NULL;
		return;
	}
	init_buffer(&buffer, 0);
	while (c != EOF && c != '\n') {
		put_buffer(&buffer, c);
		 c = get();
	}
	unget(c);
	put_buffer(&buffer, 0);
	*reason = steal_buffer(&buffer);
}

bool parse_exxe_output(struct exxe_output *output)
{
	int c = get();
	unsigned int i;

	output->reason = NULL;
	while (c == ' ' || c == '\t' || c == '\n')
		c = get();
	switch(c) {
	case '>':
		parse_data(&output->output);
		output->what = '1';
		return true;
	case '2':
		c = get();
		if (c != '>')
			fatal("invalid command '%c'", c);
		parse_data(&output->error);
		output->what = '2';
		return true;
	case '?':
		parse_space(c);
		c = get();
		if (c != '(')
			unget(c);
		if (!parse_number(&i))
			fatal("Number expected in command '?'");
		if (c == '(') {
			c = get();
			if (c != ')')
				fatal("Expected ')' in command '?'");
			c = '(';
		}
		output->what = '?';
		output->status = c == '(' ? W_EXITCODE(0, i) : W_EXITCODE(i, 0);
		parse_reason(&output->reason);
		return true;
	default:
		if (c != EOF)
			fatal("Invalid command '%c'", c);
		return false;
	}
}

void init_command(struct command *command)
{
	command->argv = NULL;
	command->argc = 0;
}

void free_command(struct command *command)
{
	if (command->argv) {
		int n;

		for (n = 0; n < command->argc; n++)
			free(command->argv[n]);
		free(command->argv);
		init_command(command);
	}
}

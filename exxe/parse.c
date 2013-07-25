#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include "buffer.h"
#include "error.h"
#include "parse.h"

static int input(void)
{
	return fgetc(stdin);
}

static void unput(int c)
{
	if (c != EOF)
		ungetc(c, stdin);
}

static bool parse_number(unsigned int *number)
{
	struct buffer buffer;
	int c = input();

	if (!(c >= '0' && c <= '9')) {
		unput(c);
		return false;
	}
	init_buffer(&buffer);
	put_buffer(&buffer, c);
	for(;;) {
		c = input();
		if (!(c >= '0' && c <= '9')) {
			unsigned long l;
			char *end;

			unput(c);
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
	c = input();
	if (c != ' ')
		unput(c);
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
			c = input();
			if (c == EOF)
				break;
			put_buffer(buffer, c);
			if (c == '\n')
				break;
		}
	}
}

static void parse_single_quoted(struct buffer *buffer)
{
	int c = input();

	while (c != EOF && c != '\'') {
		put_buffer(buffer, c);
		c = input();
	}
	if (c == EOF)
		fatal("Unexpected EOF while looking for matching single quote");
}

static bool parse_word(struct buffer *buffer, bool *more)
{
	bool defined = false;
	int c = input();

	while (c == ' ' || c == '\t')
		c = input();
	for(;;) {
		switch(c) {
		case EOF:
			goto out;
		case '\'':
			defined = true;
			parse_single_quoted(buffer);
			break;
		case '\\':
			c = input();
			if (c == EOF)
				fatal("Unexpected EOF after backslash");
			if (c == '\n')
				break;
			goto escaped;
		case ' ': case '\t':
			*more = true;
			goto out;
		case '\n':
			*more = false;
			goto out;
		escaped: default:
			defined = true;
			put_buffer(buffer, c);
		}
		c = input();
	}

out:
	put_buffer(buffer, 0);
	return defined;
}

static unsigned int count_args(char **argv)
{
	unsigned int argc = 0;
	while (*argv++)
		argc++;
	return argc;
}

static void put_arg(char ***argv, char *arg)
{
	unsigned int argc = *argv ? count_args(*argv) : 0;

	*argv = xrealloc(*argv, (argc + 2) * sizeof(**argv));
	(*argv)[argc++] = arg;
	(*argv)[argc++] = NULL;
}

static void parse_command(char ***argv)
{
	int c = input();

	if (c != ' ')
		unput(c);
	for(;;) {
		struct buffer buffer;
		bool more = false;

		init_buffer(&buffer);
		if (!parse_word(&buffer, &more)) {
			if (*argv)
				return;
			fatal("Unexpected EOF while looking for a word");
		}
		put_arg(argv, steal_buffer(&buffer));
		if (!more)
			return;
	}
}

bool parse_input(struct input_command *command)
{
	int c = input();

	while (c == ' ' || c == '\t' || c == '\n')
		c = input();
	switch(c) {
	case '>':  /* standard input */
		parse_data(&command->input);
		command->command = c;
		return true;
	case '!':  /* command to run */
		parse_command(&command->argv);
		command->command = c;
		return true;
	default:
		if (c != EOF)
			fatal("Invalid command '%c'", c);
		return false;
	}
}

static void parse_number_and_garbage(unsigned int *number, char command)
{
	int c = input();

	while (c == ' ' || c == '\t')
		c = input();
	unput(c);
	if (!parse_number(number))
		fatal("Number expected in command '%c'", command);

	c = input();
	while (c != EOF && c != '\n')
		c = input();
}

bool parse_output(struct output_command *command)
{
	int c = input();

	while (c == ' ' || c == '\t' || c == '\n')
		c = input();
	switch(c) {
	case '>':
		parse_data(&command->output);
		command->command = '1';
		return true;
	case '2':
		c = input();
		if (c != '>')
			fatal("invalid command '%c'", c);
		parse_data(&command->error);
		command->command = '2';
		return true;
	case '?':
		parse_number_and_garbage(&command->status, c);
		command->command = c;
		return true;
	case '$':
		parse_number_and_garbage(&command->signal, c);
		command->command = c;
		return true;
	default:
		if (c != EOF)
			fatal("Invalid command '%c'", c);
		return false;
	}
}

void free_argv(char **argv)
{
	int n;

	if (argv) {
		for (n = 0; argv[n]; n++)
			free(argv[n]);
		free(argv);
	}
}
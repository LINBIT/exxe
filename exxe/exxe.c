/* exxe.c */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <locale.h>
#include <getopt.h>
#include <stdarg.h>

#include "xalloc.h"
#include "buffer.h"
#include "parse.h"
#include "error.h"

#define max(a, b) (((a) > (b)) ? (a) : (b))

static struct option long_options[] = {
	{"no-stdin", no_argument, 0, 'n' },
	{"in",       no_argument, 0, 'i' },
	{"in-from",  required_argument, 0, 'I' },
	{"out",      no_argument, 0, 'o' },
	{"out-to",   required_argument, 0, 'O' },
	{"version",  no_argument, 0, 'v' },
	{"help",     no_argument, 0, 'h' },
	{}
};

const char *progname;

enum { WITH_STDIN = 1 };

static bool is_printable(const char *s, size_t len)
{
	const char *end = s + len;

	if (!(len && *(end - 1) == '\n'))
		return false;
	for (end--; s != end; s++) {
		if (*s == '\n' || !isprint(*s))
			return false;
	}
	return true;
}

static void print_str(const char *str, int size, int std_fd)
{
	if (std_fd != -1)
		printf("%u", std_fd);
	if (is_printable(str, size))
		printf("> %.*s", size, str);
	else if (str[size - 1] == '\n')
		printf(">%u %.*s", size, size, str);
	else
		printf(">%u %.*s\n", size, size, str);
}

static void print_buffer(struct buffer *buffer, int std_fd)
{
	char *s = buffer_read_pos(buffer);
	size_t size = buffer_size(buffer);
	while (size) {
		char *nl = memchr(s, '\n', size);
		int l = nl ? nl - s + 1 : size;

		print_str(s, l, std_fd);
		s += l;
		size -= l;
	}
}

static int read_from(struct buffer *buffer, int *pfd, int std_fd, const char *which)
{
	ssize_t ret;

	grow_buffer(buffer, 4096);
	for(;;) {
		ret = read(*pfd, buffer_write_pos(buffer), buffer_available(buffer));
		if (ret <= 0)
			break;
		buffer_advance_write(buffer, ret);
	}
	if (ret == 0) {
		close(*pfd);
		*pfd = -1;
		return 0;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;
	fprintf(stderr, "Reading from %s: %s\n",
		which,
		strerror(errno));
	return -1;
}

static int write_to(int *pfd, struct buffer *buffer, const char *which)
{
	ssize_t ret;

	ret = write(*pfd, buffer_read_pos(buffer), buffer_size(buffer));
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		fprintf(stderr, "Writing to %s: %s\n",
			which,
			strerror(errno));
		return -1;
	}
	buffer_advance_read(buffer, ret);

	if (!buffer_size(buffer)) {
		close(*pfd);
		*pfd = -1;
	}

	return 0;
}

static void print_errno_error(const char *command)
{
	static char *out_of_memory = "Out of memory\n";
	int size;
	char *message = NULL;

	size = asprintf(&message, "%s: %s: %s\n",
			progname, command, strerror(errno));
	if (size < 0) {
		message = out_of_memory;
		size = strlen(out_of_memory);
	}
	print_str(message, strlen(message), 2);
	if (message != out_of_memory)
		free(message);
}

static int do_chdir(char *argv[], struct buffer *in_buffer)
{
	if (!argv[1]) {
		errno = ENOTSUP;
		return -1;
	}
	return chdir(argv[1]);
}

static int do_export(char *argv[], struct buffer *in_buffer)
{
	char *name = NULL;
	const char *eq = NULL;

	if (!argv[1]) {
		errno = ENOTSUP;
		return -1;
	}
	for (argv++; *argv; argv++) {
		const char *value;
		int ret;

		eq = strchr(*argv, '=');
		if (eq) {
			name = strndup(*argv, eq - *argv);
			value = eq + 1;
			ret = setenv(name, value, 1);
			free(name);
			if (ret != 0)
				return -1;
		}
	}
	return 0;
}

static int do_umask(char *argv[], struct buffer *in_buffer)
{
	unsigned long mask;
	char *end;

	if (!argv[1]) {
		int mask;

		mask = umask(0); umask(mask);
		printf("> %04o\n", mask);
		return 0;
	}
	mask = strtoul(argv[1], &end, 8);
	if (*end || mask > 0777) {
		errno = EINVAL;
		return -1;
	}
	umask(mask);
	return 0;
}

struct internal_command {
	const char *name;
	int (*command)(char *argv[], struct buffer *in_buffer);
};

struct internal_command internal_commands[] = {
	{"cd", do_chdir},
	{"export", do_export},
	{"umask", do_umask},
	{}
};

static bool do_internal(char *argv[], struct buffer *in_buffer)
{
	struct internal_command *command;

	for (command = internal_commands; command->name; command++) {
		if (!strcmp(argv[0], command->name)) {
			int ret;

			ret = command->command(argv, in_buffer);
			if (ret < 0) {
				print_errno_error(argv[0]);
				ret = 1;
			}
			printf("? %d\n", ret);
			return true;
		}
	}
	return false;
}

int run_command(const char *file, char *argv[], struct buffer *in_buffer, int flags)
{
	static int dev_null = -1;
	pid_t pid;
	int in[2], out[2], err[2];
	int ret;

	if (do_internal(argv, in_buffer))
		return 0;

	if (in_buffer) {
		ret = pipe2(in, O_CLOEXEC);
		if (ret != 0)
			return -1;
	} else {
		in[0] = -1;
		in[1] = -1;
	}
	ret = pipe2(out, O_CLOEXEC);
	if (ret != 0)
		return -1;
	ret = pipe2(err, O_CLOEXEC);
	if (ret != 0)
		return -1;

	if (!in_buffer && !(flags & WITH_STDIN) && dev_null == -1) {
		dev_null = open("/dev/null", O_RDONLY);
		if (dev_null < 0) {
			perror("/dev/null");
			exit(1);
		}
	}

	pid = fork();
	if (pid) {
		struct buffer out_buffer, err_buffer;
		int status;

		if (in[0] != -1)
			close(in[0]);
		close(out[1]);
		close(err[1]);

		if (in[1] != -1)
			fcntl(in[1], F_SETFL, O_NONBLOCK);
		fcntl(out[0], F_SETFL, O_NONBLOCK);
		fcntl(err[0], F_SETFL, O_NONBLOCK);

		init_buffer(&out_buffer, 1 << 12);
		init_buffer(&err_buffer, 1 << 12);

		for(;;) {
			int nfds = 0;

			fd_set rfds, wfds;

			FD_ZERO(&rfds);
			if (out[0] != -1) {
				FD_SET(out[0], &rfds);
				nfds = max(nfds, out[0]) + 1;
			}
			if (err[0] != -1) {
				FD_SET(err[0], &rfds);
				nfds = max(nfds, err[0]) + 1;
			}
			FD_ZERO(&wfds);
			if (in[1] != -1) {
				FD_SET(in[1], &wfds);
				nfds = max(nfds, in[1]) + 1;
			}
			if (nfds == 0)
				break;
			ret = select(nfds, &rfds, &wfds, NULL, NULL);
			if (ret == -1) {
				perror("running command");
				return -1;
			}
			if (ret) {
				if (FD_ISSET(in[1], &wfds))
					write_to(&in[1], in_buffer, "standard input");
				if (FD_ISSET(out[0], &rfds))
					read_from(&out_buffer, &out[0], -1, "standard output");
				if (FD_ISSET(err[0], &rfds))
					read_from(&err_buffer, &err[0], 2, "standard error");
			}
		}

		print_buffer(&out_buffer, -1);
		print_buffer(&err_buffer, 2);

		for(;;) {
			ret = waitpid(pid, &status, 0);
			if (ret != pid)
				return -1;
			if (!(WIFSTOPPED(status) || WIFCONTINUED(status)))
				break;
		}
		if (WIFEXITED(status))
			printf("? %d\n", WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			printf("$ %u %s\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
		else
			printf("?\n");
		fflush(stdout);

		free_buffer(&out_buffer);
		free_buffer(&err_buffer);
	} else {
		setpgrp();
		if (!(flags & WITH_STDIN))
			dup2(in[0] == -1 ? dev_null : in[0], 0);
		dup2(out[1], 1);
		dup2(err[1], 2);
		execvp(file, argv);
		fprintf(stderr, "%s: %s\n", file, strerror(errno));
		exit(127);
	}
	return 0;
}

static bool strchrs(const char *any, const char *str)
{
	for (; *str; str++)
		if (strchr(any, *str))
			return true;
	return false;
}

static void print_arg(const char *arg)
{
	if (!*arg || strchrs("\\\'\"$ \t\n", arg)) {
		bool single_quoted = false;

		if (!*arg ||
		    (strchrs(" \t\n", arg) &&
		     !strchr("\\\'", *arg))) {
			fputc('\'', stdout);
			single_quoted = true;
		}
		for (; *arg; arg++) {
			if (strchr("\\\'", *arg)) {
				if (single_quoted) {
					fputc('\'', stdout);
					single_quoted = false;
				}
				fputc('\\', stdout);
				fputc(*arg, stdout);
				if (strchrs(" \t\n", arg + 1) &&
				    !strchr("\\\'", arg[1])) {
					fputc('\'', stdout);
					single_quoted = true;
				}
			} else {
				if (strchr("\"$", *arg) && !single_quoted)
					fputc('\\', stdout);
				fputc(*arg, stdout);
			}
		}
		if (single_quoted)
			fputc('\'', stdout);
	} else
		fputs(arg, stdout);
}

static void usage(const char *fmt, ...)
{
	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputs("\n\n", stderr);
	}
	fputs(
"Execute commands indirectly.  This utility can be used in four different\n"
"modes:\n"
"\n"
"  " PACKAGE_NAME "\n"
"    Act as a server: execute commands read from standard input, and report\n"
"    the results on standard output.\n"
"\n"
"  " PACKAGE_NAME " -i [-n] {command} ...\n"
"    Produce the input the server expects for running {command}.  By default,\n"
"    the standard input is passed on to the server; the -n option can be used\n"
"    to prevent that.  Can be run multiple times to send multiple commands\n"
"    to a server.\n"
"\n"
"  " PACKAGE_NAME " -o\n"
"    Read and process the server's output: produce the same output as the\n"
"    command executed by the server, and terminate with the same exit status\n"
"    or signal.  Can be rerun to read the output of the next command.\n"
"\n"
"  " PACKAGE_NAME " [-n] {command}\n"
"    Execute {command} directly, but produce the same output that the\n"
"    utility would produce in server mode.  The -n option can be used to\n"
"    prevent the utility from reading from standard input.\n"
"\n"
"The following is roughly equivalent to running {command} directly:\n"
"  " PACKAGE_NAME " [-n] -i {command} | " PACKAGE_NAME " | " PACKAGE_NAME " -o\n", fmt ? stdout : stderr);
	exit(fmt ? 2 : 0);
}

static int use_fd_or_open_file(const char *opt, int flags)
{
	char *end;
	int fd;

	fd = strtoul(opt, &end, 10);
	if (!*end) {
		if (fcntl(fd, F_GETFD) >= 0)
			return fd;
	}
	fd = open(opt, flags);
	if (fd < 0)
		fatal("%s: %s", opt, strerror(errno));
	return fd;
}

int main(int argc, char *argv[])
{
	int opt_input = -1, opt_output = -1;
	int opt_server = false, opt_test = false;
	bool opt_stdin = true;

	progname = basename(argv[0]);

	for(;;) {
		int c;

		c = getopt_long(argc, argv, "+niI:oO:vh", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
		case 'i':
			optarg = NULL;
			/* fall through */
		case 'I':
			/* write to standard output by default */
			opt_input = optarg ? use_fd_or_open_file(optarg, O_WRONLY) : 1;
			break;
		case 'o':
			optarg = NULL;
			/* fall through */
		case 'O':
			/* read from standard input by default */
			opt_output = optarg ? use_fd_or_open_file(optarg, O_RDONLY) : 0;
			break;
		case 'n':
			/* Redirect standard input to /dev/null.  Only
			 * effective when passing the command to run on the
			 * command line; otherwise, we never read from
			 * exxe's standard input.  */
			opt_stdin = false;
			break;
		case 'v':
			printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			exit(0);
			break;
		case 'h':
			usage(NULL);
		case '?':
			break;
		};
	}

	if (opt_input == -1 && opt_output == -1) {
		opt_server = optind == argc;
		opt_test = !opt_server;
	}

	init_buffer(&expanded_input, 0);

	if (opt_input != -1) {
		int stdout_dup = -1;

		/* input to server */

		if (opt_input != 1) {
			stdout_dup = dup(1);
			if (stdout_dup < 0)
				fatal("duplicating standard output");
			if (dup2(opt_input, 1) < 0)
				fatal("file descriptor %d: %s", opt_input, strerror(errno));
		}

		if (optind == argc)
			usage("command-line arguments missing");

		if (opt_stdin) {
			struct buffer in_buffer;

			init_buffer(&in_buffer, 1 << 12);
			for(;;) {
				size_t size;

				grow_buffer(&in_buffer, 1);
				size = fread(buffer_write_pos(&in_buffer), 1, buffer_available(&in_buffer), stdin);
				if (ferror(stdin))
					fatal("Error reading from standard input");
				buffer_advance_write(&in_buffer, size);
				if (feof(stdin))
					break;
			}
			print_buffer(&in_buffer, -1);
			free_buffer(&in_buffer);
		}
		fputc('!', stdout);
		for (; optind < argc; optind++) {
			fputc(' ', stdout);
			print_arg(argv[optind]);
		}
		fputc('\n', stdout);
		if (fflush(stdout) != 0)
			fatal("writing");
		if (stdout_dup != -1) {
			if (dup2(stdout_dup, 1) < 0)
				fatal("restoring standard output");
			close(stdout_dup);
			if (close(opt_input))
				fatal("closing file descriptor for writing");
		}
	}
	if (opt_output != -1) {
		struct output_command command;
		int stdin_dup = -1;

		/* output from server */

		if (opt_output != 0) {
			stdin_dup = dup(0);
			if (stdin_dup < 0)
				fatal("duplicating standard input");
			if (dup2(opt_output, 0) < 0)
				fatal("file descriptor %d: %s", opt_output, strerror(errno));
		}

		if (optind != argc)
			usage("no command-line arguments allowed");

		init_buffer(&command.output, 1 << 12);
		init_buffer(&command.error, 1 << 12);

		for(;;) {
			if (!parse_output(&command))
				fatal("Unexpected EOF while reading the command output");
			switch(command.command) {
			case '1':
				fwrite(buffer_read_pos(&command.output), 1,
				       buffer_size(&command.output), stdout);
				reset_buffer(&command.output);
				break;
			case '2':
				fwrite(buffer_read_pos(&command.error), 1,
				       buffer_size(&command.error), stderr);
				reset_buffer(&command.error);
				break;
			case '?':
				exit(command.status);
			case '$':
				kill(getpid(), command.signal);
				exit(0);
			}
		}

		if (stdin_dup != -1) {
			if (dup2(stdin_dup, 0) < 0);
				fatal("restoring standard input");
			close(stdin_dup);
			if (close(opt_output))
				fatal("closing file descriptor for reading");
		}
	}
	if (opt_server) {
		struct input_command command;

		/* server mode */

		init_buffer(&command.input, 1 << 12);
		command.argv = NULL;
		opt_stdin = false;

		for(;;) {
			if (!parse_input(&command))
				break;
			switch(command.command) {
			case '>':
				break;
			case '!':
				run_command(command.argv[0], command.argv, &command.input, 0);
				reset_buffer(&command.input);
				free_argv(command.argv);
				command.argv = NULL;
				break;
			}
		}
		free_buffer(&command.input);
		free_argv(command.argv);
	}
	if (opt_test) {

		/* test mode */

		char *args[argc - optind + 1];
		int n;

		if (optind == argc)
			usage("no command specified");

		setlocale(LC_CTYPE, NULL);
		for (n = optind; n < argc; n++)
			args[n - optind] = argv[n];
		args[n - optind] = NULL;
		run_command(args[0], args, NULL, opt_stdin ? WITH_STDIN : 0);
	}
	return 0;
}

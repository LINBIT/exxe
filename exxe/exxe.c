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
#include <math.h>
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
	{"prefix",   required_argument, 0, 'p' },
	{"error-prefix", required_argument, 0, 'P' },
	{"no-quote", no_argument, 0, 'Q' },
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

static void write_output(struct buffer *buffer, FILE *file, const char *prefix)
{
	const char *text = buffer_read_pos(buffer);
	size_t size = buffer_size(buffer);

	if (prefix) {
		while (size) {
			char *nl = memchr(text, '\n', size);
			size_t len = nl ? nl - text + 1 : size;

			fputs(prefix, file);
			fwrite(text, 1, len, file);
			text += len;
			size -= len;
		}
	} else
		fwrite(text, 1, size, file);
	fflush(file);
	reset_buffer(buffer);
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

struct {
	struct buffer in_buffer;
	char **argv;
} onexit;

static int do_onexit(char *argv[], struct buffer *in_buffer)
{
	int argc;

	if (!argv[1]) {
		errno = EINVAL;
		return -1;
	}

	if (onexit.argv) {
		for (argc = 0; onexit.argv[argc]; argc++)
			free(onexit.argv[argc]);
	}

	if (!strcmp(argv[1], "-")) {
		free(onexit.argv);
		onexit.argv = NULL;
	} else {
		for (argc = 1; argv[argc]; argc++)
			/* do nothing */ ;
		onexit.argv = xrealloc(onexit.argv,
			(argc + 1) * sizeof(onexit.argv[0]));
		for (argc = 1; argv[argc]; argc++)
			onexit.argv[argc - 1] = xstrdup(argv[argc]);
		onexit.argv[argc - 1] = NULL;

		reset_buffer(&onexit.in_buffer);
		if (in_buffer && buffer_size(in_buffer)) {
			size_t size;

			size = buffer_size(in_buffer);
			grow_buffer(&onexit.in_buffer, size);
			memcpy(buffer_write_pos(&onexit.in_buffer),
			       buffer_read_pos(in_buffer), size);
			buffer_advance_write(&onexit.in_buffer, size);
			buffer_advance_read(in_buffer, size);
		}
	}
	return 0;
}

struct timespec timeout;

static int do_timeout(char *argv[], struct buffer *in_buffer)
{
	double t, frac;
	char *end;

	if (!argv[1]) {
		printf("> %g\n", timeout.tv_sec + timeout.tv_nsec * 1e-9);
		return 0;
	}
	t = strtod(argv[1], &end);
	if (*end || t < 0) {
		errno = EINVAL;
		return -1;
	}
	frac = modf(t, &t);
	timeout.tv_sec = floor(t);
	timeout.tv_nsec = floor(frac * 1e9);
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
	{"onexit", do_onexit},
	{"timeout", do_timeout},
	{"umask", do_umask},
	{}
};

static int do_internal(char *argv[], struct buffer *in_buffer)
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
			return W_EXITCODE(ret, 0);
		}
	}
	return -1;
}

static volatile sig_atomic_t got_child_sig;

static void child_sig_handler(int sig)
{
	got_child_sig = 1;
}

static void set_signals(void)
{
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL))
		fatal("blocking SIGCHLD signal");

	sa.sa_flags = 0;
	sa.sa_handler = child_sig_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL))
		fatal("setting SIGCHLD signal");
}

static void run_command(char *argv[], struct buffer *in_buffer, int flags)
{
	static int dev_null = -1;
	pid_t pid;
	int in[2], out[2], err[2];
	int killed_by = 0, status, ret;

	status = do_internal(argv, in_buffer);
	if (status != -1)
		goto out;

	if (in_buffer && buffer_size(in_buffer)) {
		ret = pipe2(in, O_CLOEXEC);
		if (ret != 0)
			fatal("creating pipe");
	} else {
		in[0] = -1;
		in[1] = -1;
	}
	ret = pipe2(out, O_CLOEXEC);
	if (ret != 0)
		fatal("creating pipe");
	ret = pipe2(err, O_CLOEXEC);
	if (ret != 0)
		fatal("creating pipe");

	if (!in_buffer && !(flags & WITH_STDIN) && dev_null == -1) {
		dev_null = open("/dev/null", O_RDONLY);
		if (dev_null < 0) {
			perror("/dev/null");
			exit(1);
		}
	}

	got_child_sig = 0;

	pid = fork();
	if (pid) {
		struct buffer out_buffer, err_buffer;
		sigset_t empty_mask;

		sigemptyset(&empty_mask);

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
			struct timespec tmp, *ptimeout;

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
			if (nfds == 0 && got_child_sig)
				break;

			if (killed_by == SIGKILL ||
			    (timeout.tv_sec == 0 && timeout.tv_nsec == 0))
				ptimeout = NULL;
			else {
				tmp = timeout;
				ptimeout = &tmp;
			}

			ret = pselect(nfds, &rfds, &wfds, NULL, ptimeout, &empty_mask);
			if (ret == -1) {
				if (errno != EINTR)
					fatal("waiting for command");
			} else if (ret == 0) {
				switch(killed_by) {
				case 0:
					/* Allow the command to terminate in a
					   controlled way.  */
					killed_by = SIGTERM;
					kill(pid, killed_by);
					break;
				case SIGTERM:
					/* The command didn't react; use force
					   and kill the entire process group.  */
					killed_by = SIGKILL;
					killpg(pid, killed_by);
					break;
				case SIGKILL:
					break;
				}
			} else {
				if (FD_ISSET(in[1], &wfds))
					write_to(&in[1], in_buffer, "standard input");
				if (FD_ISSET(out[0], &rfds))
					read_from(&out_buffer, &out[0], -1, "standard output");
				if (FD_ISSET(err[0], &rfds))
					read_from(&err_buffer, &err[0], 2, "standard error");
			}
		}

		print_buffer(&out_buffer, -1);
		free_buffer(&out_buffer);
		print_buffer(&err_buffer, 2);
		free_buffer(&err_buffer);

		for(;;) {
			ret = waitpid(pid, &status, 0);
			if (ret != pid)
				fatal("waiting for command");
			if (!(WIFSTOPPED(status) || WIFCONTINUED(status)))
				break;
		}
	} else {
		setpgrp();
		if (!(flags & WITH_STDIN))
			dup2(in[0] == -1 ? dev_null : in[0], 0);
		dup2(out[1], 1);
		dup2(err[1], 2);
		execvp(argv[0], argv);
		fprintf(stderr, "%s: %s\n", argv[0], strerror(errno));
		exit(127);
	}
out:
	if (killed_by)
		printf("$ %u Timeout\n", killed_by);
	else if (WIFEXITED(status))
		printf("? %d\n", WEXITSTATUS(status));
	else if (WIFSIGNALED(status)) {
		printf("$ %u %s\n",
		       WTERMSIG(status),
		       strsignal(WTERMSIG(status)));
	} else
		printf("?\n");
	fflush(stdout);
}

static bool strchrs(const char *any, const char *str)
{
	for (; *str; str++)
		if (strchr(any, *str))
			return true;
	return false;
}

static void print_arg(const char *arg, bool quote)
{
	if (quote && (!*arg || strchrs("\\\'\"$ \t\n", arg))) {
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
	} else {
		/* FIXME: Escape newlines if they are outside quotes! */
		fputs(arg, stdout);
	}
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
"  " PACKAGE_NAME " [-nQ] -i {command} ...\n"
"    Produce the input the server expects for running {command}.  By default,\n"
"    the standard input is passed on to the server, and the command and its\n"
"    arguments are protected from word splitting or environment variable\n"
"    interpolation.  Use the -n option to not pass standard input on to the\n"
"    server, and the -Q option to perform environment variable interpolation\n"
"    and word splitting on the server.\n"
"\n"
"  " PACKAGE_NAME " [--prefix=...] [--error-prefix=...] -o\n"
"    Read and process the server's output: produce the same output as the\n"
"    command executed by the server, and terminate with the same exit status\n"
"    or signal.  A prefix for each line of output (for all output or only for\n"
"    error output) can be specified.\n"
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
	bool opt_stdin = true, opt_quote = true;
	const char *opt_prefix = NULL, *opt_error_prefix = NULL;

	progname = basename(argv[0]);

	for(;;) {
		int c;

		c = getopt_long(argc, argv, "+niI:oO:Qvh", long_options, NULL);
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
		case 'p':
			opt_prefix = optarg;
			break;
		case 'P':
			opt_error_prefix = optarg;
			break;
		case 'Q':
			opt_quote = false;
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
			exit(2);
		};
	}

	if (opt_prefix && !opt_error_prefix)
		opt_error_prefix = opt_prefix;

	if (opt_input == -1 && opt_output == -1) {
		opt_server = optind == argc;
		opt_test = !opt_server;
	}

	init_buffer(&expanded_input, 0);
	init_buffer(&onexit.in_buffer, 0);
	onexit.argv = NULL;

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
			print_arg(argv[optind], opt_quote);
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
				write_output(&command.output, stdout, opt_prefix);
				break;
			case '2':
				write_output(&command.error, stderr, opt_error_prefix);
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

		set_signals();
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
				run_command(command.argv, &command.input, 0);
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
		char *args[argc - optind + 1];
		int n;

		/* test mode */

		set_signals();
		setlocale(LC_CTYPE, NULL);
		for (n = optind; n < argc; n++)
			args[n - optind] = argv[n];
		args[n - optind] = NULL;
		run_command(args, NULL, opt_stdin ? WITH_STDIN : 0);
	}

	if (onexit.argv)
		run_command(onexit.argv, &onexit.in_buffer, 0);

	return 0;
}

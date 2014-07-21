/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

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
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <locale.h>
#include <getopt.h>
#include <stdarg.h>
#include <syslog.h>

#include "xalloc.h"
#include "buffer.h"
#include "parse.h"
#include "error.h"

#define max(a, b) (((a) > (b)) ? (a) : (b))

static struct option long_options[] = {
	{"stdin", no_argument, 0, 'p' },
	{"in",       no_argument, 0, 'i' },
	{"in-from",  required_argument, 0, 'I' },
	{"out",      no_argument, 0, 'o' },
	{"out-to",   required_argument, 0, 'O' },
	{"prefix",   required_argument, 0, 1 },
	{"error-prefix", required_argument, 0, 2 },
	{"syslog",   no_argument, 0, 3 },
	{"logfile",  required_argument, 0, 4 },
	{"timeout",  required_argument, 0, 5 },
	{"no-quote", no_argument, 0, 'Q' },
	{"version",  no_argument, 0, 'v' },
	{"help",     no_argument, 0, 'h' },
	{}
};

const char *progname;

bool read_from_stdin;
bool log_to_syslog, log_to_logfile;
const char *opt_prefix = NULL, *opt_error_prefix = NULL;
FILE *logfile;

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

static void print_str(const char *str, int size, int fd)
{
	char inout = fd ? '>' : '<';

	if (fd != 0 && fd != 1)
		printf("%u", fd);
	if (is_printable(str, size))
		printf("%c %.*s", inout, size, str);
	else if (str[size - 1] == '\n')
		printf("%c%u %.*s", inout, size, size, str);
	else
		printf("%c%u %.*s\n", inout, size, size, str);
}

static void print_buffer(struct buffer *buffer, int fd)
{
	char *s = buffer_read_pos(buffer);
	size_t size = buffer_size(buffer);
	while (size) {
		char *nl = memchr(s, '\n', size);
		int l = nl ? nl - s + 1 : size;

		print_str(s, l, fd);
		s += l;
		size -= l;
	}
}

static int read_from(struct buffer *buffer, int *pfd, const char *which)
{
	ssize_t ret;

	grow_buffer(buffer, 4096);
	for(;;) {
		ret = TEMP_FAILURE_RETRY(
			read(*pfd,
			     buffer_write_pos(buffer),
			     buffer_available(buffer)));
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
	struct command command;
} onexit;

static int do_onexit(char *argv[], struct buffer *in_buffer)
{
	if (!argv[1]) {
		errno = EINVAL;
		return -1;
	}

	free_command(&onexit.command);
	if (strcmp(argv[1], "-") || argv[2]) {
		for (argv++; *argv; argv++)
			put_arg(&onexit.command, xstrdup(*argv));
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

static int parse_timeout(struct timespec *tv, const char *str)
{
	double t, frac;
	char *end;

	t = strtod(str, &end);
	if (*end || t < 0) {
		errno = EINVAL;
		return -1;
	}
	frac = modf(t, &t);
	tv->tv_sec = floor(t);
	tv->tv_nsec = floor(frac * 1e9);
	return 0;
}

static int do_timeout(char *argv[], struct buffer *in_buffer)
{
	if (!argv[1]) {
		printf("> %g\n", timeout.tv_sec + timeout.tv_nsec * 1e-9);
		return 0;
	}
	return parse_timeout(&timeout, argv[1]);
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

static bool do_internal(struct command *command, struct buffer *in_buffer)
{
	struct internal_command *internal_command;

	for (internal_command = internal_commands;
	     internal_command->name;
	     internal_command++) {
		if (!strcmp(command->argv[0], internal_command->name)) {
			int ret;

			ret = internal_command->command(command->argv, in_buffer);
			if (ret < 0) {
				print_errno_error(command->argv[0]);
				ret = 1;
			}
			command->status = W_EXITCODE(ret, 0);
			return true;
		}
	}
	return false;
}

static volatile sig_atomic_t got_child_sig;

static void child_sig_handler(int sig)
{
	got_child_sig = 1;
}

static void set_signals_for_commands(void)
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
		fatal("setting SIGCHLD handler");
}

static void alarm_sig_handler(int sig)
{
	fatal("%sTimeout", opt_error_prefix ? opt_error_prefix : "");
}

static void set_signals_for_io(void)
{
	struct sigaction sa;

	sa.sa_flags = 0;
	sa.sa_handler = alarm_sig_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL))
		fatal("setting SIGALRM handler");
}

static void logit(const char *fmt, ...)
{
	static char *ident;
	const char *new_ident;
	va_list ap;

	if (!(log_to_syslog || log_to_logfile))
		return;

	new_ident = getenv("EXXE_IDENT");
	if (!(new_ident && *new_ident))
		new_ident = progname;
	if (!ident || strcmp(new_ident, ident)) {
		if (ident && log_to_syslog)
			closelog();
		free(ident);
		ident = xstrdup(new_ident);
		if (log_to_syslog)
			openlog(ident, 0, LOG_USER);
	}

	va_start(ap, fmt);
	if (log_to_syslog) {
		va_list ap2;

		va_copy(ap2, ap);
		vsyslog(LOG_USER | LOG_INFO, fmt, ap);
		va_end(ap);
	}
	if (logfile) {
		struct timeval tv;
		struct tm *tm;
		va_list ap2;

		gettimeofday(&tv, NULL);
		tm = localtime(&tv.tv_sec);
		fprintf(logfile,
			"%04u-%02u-%02uT%02u:%02u:%02u.%06u%+03d:%02u %s ",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec,
			(int)tv.tv_usec,
			(int)(tm->tm_gmtoff / 3600),
			(int)((abs(tm->tm_gmtoff) / 60) % 60),
			ident);
		va_copy(ap2, ap);
		vfprintf(logfile, fmt, ap2);
		va_end(ap2);
		fprintf(logfile, "\n");
		fflush(logfile);
	}
	va_end(ap);
}

static void log_command(int argc, char *argv[])
{
	if (log_to_syslog || log_to_logfile) {
		int optind;
		char *str, *s;

		for (optind = 0, s = NULL; argv[optind]; optind++)
			s += strlen(argv[optind]) + 1;
		str = xalloc(s - (char *)NULL + 1);
		for (optind = 0, s = str; argv[optind]; optind++) {
			size_t len = strlen(argv[optind]);

			memcpy(s, argv[optind], len);
			s += len;
			*s++ = ' ';
		}
		*(--s) = 0;
		logit("%s", str);
		free(str);
	}
}

static void log_result(const char *command, int status, const char *reason)
{
	if (log_to_syslog || log_to_logfile) {
		if (!command)
			command = "Command";
		if (WIFSIGNALED(status)) {
			logit("%s was killed by signal %u (%s)",
			      command,
			      WTERMSIG(status),
			      reason ? reason : strsignal(WTERMSIG(status)));
		} else if (WIFEXITED(status)) {
			if (WEXITSTATUS(status))
				logit("%s has exited with status %d",
				      command,
				      WEXITSTATUS(status));
		}
	}
}

static void run_command(struct command *command, struct buffer *in_buffer)
{
	static int dev_null = -1;
	pid_t pid;
	int in[2], out[2], err[2];
	int killed_by = 0, ret;
	const char *reason = NULL;

	log_command(command->argc, command->argv);
	if (do_internal(command, in_buffer))
		goto out;

	in[0] = -1;
	in[1] = -1;
	if (in_buffer) {
		if (!buffer_size(in_buffer)) {
			in_buffer = NULL;
			read_from_stdin = false;
		} else {
			ret = pipe2(in, O_CLOEXEC);
			if (ret != 0)
				fatal("creating pipe");
		}
	}
	ret = pipe2(out, O_CLOEXEC);
	if (ret != 0)
		fatal("creating pipe");
	ret = pipe2(err, O_CLOEXEC);
	if (ret != 0)
		fatal("creating pipe");

	if (!in_buffer && !read_from_stdin && dev_null == -1) {
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
					command->status = W_EXITCODE(0, killed_by);
					break;
				case SIGTERM:
					/* The command didn't react; use force
					   and kill the entire process group.  */
					killed_by = SIGKILL;
					killpg(pid, killed_by);
					command->status = W_EXITCODE(0, killed_by);
					break;
				case SIGKILL:
					break;
				}
			} else {
				if (in[1] != -1 && FD_ISSET(in[1], &wfds))
					write_to(&in[1], in_buffer, "standard input");
				if (out[0] != -1 && FD_ISSET(out[0], &rfds))
					read_from(&out_buffer, &out[0], "standard output");
				if (FD_ISSET(err[0], &rfds))
					read_from(&err_buffer, &err[0], "standard error");
			}
		}

		print_buffer(&out_buffer, 1);
		free_buffer(&out_buffer);
		print_buffer(&err_buffer, 2);
		free_buffer(&err_buffer);

		for(;;) {
			ret = waitpid(pid, &command->status, 0);
			if (ret != pid)
				fatal("waiting for command");
			if (!(WIFSTOPPED(command->status) || WIFCONTINUED(command->status)))
				break;
		}
	} else {
		setpgrp();
		if (!read_from_stdin)
			dup2(in[0] == -1 ? dev_null : in[0], 0);
		dup2(out[1], 1);
		dup2(err[1], 2);
		execvp(command->argv[0], command->argv);
		fprintf(stderr, "%s: %s\n", command->argv[0], strerror(errno));
		exit(127);
	}
out:
	if (WIFSIGNALED(command->status))
		reason = killed_by ? "Timeout" : strsignal(WTERMSIG(command->status));
	log_result(command->argv[0], command->status, reason);
	if (WIFSIGNALED(command->status))
		printf("? (%d) %s\n", WTERMSIG(command->status), reason);
	else if (WIFEXITED(command->status))
		printf("? %d\n", WEXITSTATUS(command->status));
	else
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

static void reset_timeout(void)
{
	struct itimerval itv;

	if (timeout.tv_sec == 0 && timeout.tv_nsec == 0)
		return;
	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 0;
	itv.it_value.tv_sec = timeout.tv_sec;
	itv.it_value.tv_usec = timeout.tv_nsec / 1000;
	if (!setitimer(ITIMER_REAL, &itv, NULL))
		return;
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
"ways:\n"
"\n"
"  " PACKAGE_NAME "\n"
"    Act as a server: execute commands read from standard input, and report\n"
"    the results on standard output.\n"
"\n"
"  " PACKAGE_NAME " [-pQ] -i {command} ...\n"
"    Produce the input the server expects for running {command}.  By default,\n"
"    the standard input is not passed on to the server, and the command and\n"
"    its arguments are protected from word splitting or environment variable\n"
"    interpolation.  Use the -p option to pass standard input on to the\n"
"    server, and the -Q option to perform environment variable interpolation\n"
"    and word splitting on the server.\n"
"\n"
"  " PACKAGE_NAME " [--prefix=...] [--error-prefix=...] -o\n"
"    Read and process the server's output: produce the same output as the\n"
"    command executed by the server, and terminate with the same exit status\n"
"    or signal.  A prefix for each line of output (for all output or only for\n"
"    error output) can be specified.\n"
"\n"
"  " PACKAGE_NAME " [-p] {command}\n"
"    Execute {command} directly, but produce the same output that the\n"
"    utility would produce in server mode.  The -p option can be used to\n"
"    allow the command to read from standard input.\n"
"\n"
"Options:\n"
"  --timeout=...\n"
"    Set a timeout (or wait forever for a timeout value of 0).  The timeout\n"
"    restarts whenever a command produces some output.  If this option is\n"
"    not specified and the EXXE_TIMEOUT environment variable is set, the\n"
"    value of that variable is used.  In server mode, the built-in command\n"
"    'timeout' can be used to later change the timeout.\n"
"\n"
"  --syslog\n"
"    Log all commands to the system log.  The EXXE_IDENT environment\n"
"    variable can be used to change the syslog identifier; by default,\n"
"    " PACKAGE_NAME "'s executable name is used.\n"
"\n"
"  --logfile=filename\n"
"    Log all commands to the specified logfile.  The EXXE_IDENT environment\n"
"    variable can be used to change the syslog identifier; by default,\n"
"    " PACKAGE_NAME "'s executable name is used.\n", fmt ? stdout : stderr);
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
	bool opt_quote = true;
	const char *opt_timeout = NULL;

	progname = basename(argv[0]);

	for(;;) {
		int c;

		c = getopt_long(argc, argv, "+piI:oO:Qvh", long_options, NULL);
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
		case 1:
			opt_prefix = optarg;
			break;
		case 2:
			opt_error_prefix = optarg;
			break;
		case 'Q':
			opt_quote = false;
			break;
		case 'p':
			/* Redirect standard input to /dev/null.  Only
			 * effective when passing the command to run on the
			 * command line; otherwise, we never read from
			 * exxe's standard input.  */
			read_from_stdin = true;
			break;
		case 3:
			log_to_syslog = true;
			break;
		case 4:
			logfile = fopen(optarg, "a");
			if (!logfile)
				fatal("%s: %s", optarg, strerror(errno));
			log_to_logfile = true;
			break;
		case 5:
			opt_timeout = optarg;
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
	init_command(&onexit.command);

	if (!opt_timeout) {
		opt_timeout = getenv("EXXE_TIMEOUT");
		if (opt_timeout && !*opt_timeout)
			opt_timeout = NULL;
	}
	if (opt_timeout) {
		if (parse_timeout(&timeout, opt_timeout)) {
			fprintf(stderr, "%s: timeout value '%s': %s\n",
				progname, opt_timeout,
				strerror(errno));
			exit(2);
		}
	}

	if (opt_input == -1 || opt_output == -1)
		set_signals_for_io();

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

		if (read_from_stdin) {
			struct buffer in_buffer;

			init_buffer(&in_buffer, 1 << 12);
			for(;;) {
				ssize_t size;

				reset_timeout();
				grow_buffer(&in_buffer, 1);
				size = TEMP_FAILURE_RETRY(
					read(0,
					     buffer_write_pos(&in_buffer),
					     buffer_available(&in_buffer)));
				if (size < 0)
					fatal("Error reading from standard input");
				if (size == 0)
					break;
				buffer_advance_write(&in_buffer, size);
			}
			print_buffer(&in_buffer, 0);
			free_buffer(&in_buffer);
		}
		log_command(argc - optind, argv + optind);
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
		struct exxe_output output;
		int stdin_dup = -1;

		/* output from server */

		if (opt_output != 0) {
			stdin_dup = dup(0);
			if (stdin_dup < 0)
				fatal("duplicating standard input");
			if (dup2(opt_output, 0) < 0)
				fatal("file descriptor %d: %s",
				      opt_output, strerror(errno));
		}

		if (optind != argc)
			usage("no command-line arguments allowed");

		init_buffer(&output.output, 1 << 12);
		init_buffer(&output.error, 1 << 12);

		for(;;) {
			reset_timeout();
			if (!parse_exxe_output(&output))
				fatal("Unexpected EOF while reading the command output");
			switch(output.what) {
			case '1':
				write_output(&output.output, stdout, opt_prefix);
				break;
			case '2':
				write_output(&output.error, stderr, opt_error_prefix);
				break;
			case '?':
				log_result(NULL, output.status, output.reason);
				if (WIFSIGNALED(output.status))
					kill(getpid(), WTERMSIG(output.status));
				exit(WEXITSTATUS(output.status));
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
		struct exxe_input input;

		/* server mode */

		set_signals_for_commands();
		init_buffer(&input.input, 1 << 12);
		init_command(&input.command);
		read_from_stdin = false;

		for(;;) {
			if (!parse_exxe_input(&input))
				break;
			switch(input.what) {
			case '!':
				run_command(&input.command, &input.input);
				reset_buffer(&input.input);
				free_command(&input.command);
				break;
			}
		}
		free_buffer(&input.input);
		free_command(&input.command);
	}
	if (opt_test) {
		struct command command;

		/* test mode */

		set_signals_for_commands();
		setlocale(LC_CTYPE, NULL);
		init_command(&command);
		for (; optind < argc; optind++)
			put_arg(&command, argv[optind]);
		run_command(&command, NULL);
	}

	if (onexit.command.argc)
		run_command(&onexit.command, &onexit.in_buffer);

	return 0;
}

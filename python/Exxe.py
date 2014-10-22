#! /usr/bin/env python

import re
import os
import sys
import subprocess
import pipes
import select
import signal
import itertools
import collections

from subprocess import CalledProcessError
from StringIO import StringIO


class ProcessTimeoutError(CalledProcessError):
    def __init__(self, cmd):
	super(ProcessTimeoutError, self).__init__(-signal.SIGTERM, cmd)

    def __str__(self):
	return "Command '%s' timed out" % self.cmd


class Exxe(object):
    def __init__(self, server, timeout=None, prefix=None, error_prefix=None):
	self.server = subprocess.Popen(server, shell=True,
				       stdin=subprocess.PIPE,
				       stdout=subprocess.PIPE)
	self.timeout = timeout
	self.prefix = prefix if prefix else ''
	self.error_prefix = error_prefix if error_prefix else self.prefix

    def write_input(self, stdin):
	for line in stdin.splitlines(True):
	    if line[-1] != '\n':
		x = '<' + str(len(line)) + ' ' + line + '\n'
	    elif re.match(r'[\000-\037\200-\377]', line):
		x = '<' + str(len(line)) + ' ' + line
	    else:
		x = '< ' + line
	    os.write(self.server.stdin.fileno(), x)

    def write_command(self, cmd, quote):
	if isinstance(cmd, basestring):
	    cmd = [cmd]
	cmd = ' '.join([pipes.quote(arg) for arg in cmd] if quote else cmd)
	self.cmd = cmd
	os.write(self.server.stdin.fileno(), '! ' + cmd + '\n')

    def read_result(self, stdout, stderr):
	if stdout is not None and not isinstance(stdout, file):
	    stdout = StringIO()
	if stderr is not None and not isinstance(stderr, file):
	    stderr = StringIO()
	poller = select.poll()
	poller.register(self.server.stdout.fileno(),
			select.POLLIN | select.POLLPRI)

	def reader_generator():
	    data = ''
	    idx = 0

	    while True:
		if idx == len(data):
		    ready = poller.poll(self.timeout)
		    if not ready:
			raise ProcessTimeoutError(self.cmd)
		    data = os.read(self.server.stdout.fileno(), 4096)
		    if not data:
			raise StopIteration()
		    idx = 0
		yield data[idx]
		idx += 1
	reader = reader_generator()

	def read_number(c):
	    number = 0
	    while c >= '0' and c <= '9':
		number = (10 * number) + ord(c) - ord('0')
		c = reader.next()
	    return c, number

	def read_status():
	    # From the itertools documentation:
	    def consume(iterator):
		# feed the entire iterator into a zero-length deque
		collections.deque(iterator, maxlen=0)

	    c = reader.next()
	    if c == ' ':
		c = reader.next()
	    if c == '(':
		c, signal = read_number(reader.next())
		if c != ')':
		    raise IOError('Parsing exxe output')
		consume(itertools.takewhile(lambda c: c != '\n', reader))
		raise CalledProcessError(-signal, self.cmd)
	    else:
		c, status = read_number(c)
		if status == 0:
		    if c != '\n':
			raise IOError('Parsing exxe output')

		    def get_output(output):
			if isinstance(output, StringIO):
			    return output.getvalue()
			return None

		    return get_output(stdout), get_output(stderr)
		else:
		    raise CalledProcessError(status, self.cmd)

	def read_output(c):
	    def write_output(where, output):
		if isinstance(where, file):
		    os.write(where.fileno(), output)
		elif isinstance(where, StringIO):
		    where.write(output)

	    while c == ' ' or c == '\t' or c == '\n':
		c = reader.next()
	    if c == '2':
		where = stderr
		prefix = self.error_prefix
		c = reader.next()
	    else:
		where = stdout
		prefix = self.prefix
	    if c != '>':
		raise IOError('Parsing exxe output')
	    c = reader.next()
	    if c >= '0' and c <= '9':
		c, length = read_number(c)
		if c == ' ':
		    c = reader.next()
		read = itertools.islice(reader, length - 1)
		write_output(where, prefix + c + ''.join(read))
	    else:
		if c == ' ':
		    c = reader.next()
		if c == '\n':
		    read = []
		else:
		    read = itertools.takewhile(lambda c: c != '\n', reader)
		write_output(where, prefix + c + ''.join(read) + '\n')

	try:
	    while True:
		c = reader.next()
		if c == '?':
		    return read_status()
		else:
		    read_output(c)
	except StopIteration:
	    raise EOFError()

    def run(self, cmd, stdin=None, stdout=sys.stdout, stderr=sys.stderr,
	    quote=True):
	if stdin is not None:
	    self.write_input(stdin)
	self.write_command(cmd, quote)
	return self.read_result(stdout, stderr)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Execute commands indirectly (client).')
    parser.add_argument('cmd', nargs='+')
    parser.add_argument('-p', '--stdin', action='store_true')
    parser.add_argument('--prefix')
    parser.add_argument('--error-prefix')
    parser.add_argument('--timeout')
    parser.add_argument('-q', '--no-quote', action='store_true')
    parser.add_argument('--canonical-output', action='store_true')
    parser.add_argument('--server', required=True)
    args = parser.parse_args()

    exxe = Exxe(args.server,
		timeout=int(float(args.timeout) * 1000) if args.timeout else None,
		prefix=args.prefix,
		error_prefix=args.error_prefix)

    try:
	stdout, stderr = exxe.run(args.cmd,
				  sys.stdin.read() if args.stdin else None,
				  stdout=args.canonical_output or sys.stdout,
				  stderr=args.canonical_output or sys.stderr,
				  quote=not args.no_quote)
	if stdout:
	    os.write(sys.stdout.fileno(), stdout)
	if stderr:
	    os.write(sys.stderr.fileno(), stderr)
    except ProcessTimeoutError, error:
	print >> sys.stderr, error
	sys.exit(128 - error.returncode)
    except CalledProcessError, error:
	if error.returncode < 0:
	    # FIXME: Python seems to catch SIGINT; it doesn't get through to
	    # user space
	    os.kill(0, -error.returncode)
	else:
	    sys.exit(error.returncode)

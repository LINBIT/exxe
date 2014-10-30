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
from cStringIO import StringIO

__all__ = ['Exxe', 'run']


class ProcessTimeoutError(CalledProcessError):
    def __init__(self, cmd):
	super(ProcessTimeoutError, self).__init__(-signal.SIGTERM, cmd)

    def __str__(self):
	return "Command '%s' timed out" % self.cmd


class Exxe(object):
    def __init__(self, server, shell=False, timeout=None, prefix=None, error_prefix=None):
	self.server = subprocess.Popen(server, shell=shell,
				       stdin=subprocess.PIPE,
				       stdout=subprocess.PIPE)
	self.timeout = timeout
	self.prefix = prefix if prefix is not None else ''
	self.error_prefix = error_prefix if error_prefix is not None else self.prefix

    def write_input(self, stdin):
	for line in stdin:
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

    def read_result(self, stdout, stderr, prefix, error_prefix):
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
		else:
		    raise CalledProcessError(status, self.cmd)

	def read_output(c):
	    while c == ' ' or c == '\t' or c == '\n':
		c = reader.next()
	    if c == '2':
		where = stderr
		pfx = error_prefix
		c = reader.next()
	    else:
		where = stdout
		pfx = prefix
	    if c != '>':
		raise IOError('Parsing exxe output')
	    c = reader.next()
	    if c >= '0' and c <= '9':
		c, length = read_number(c)
		if c == ' ':
		    c = reader.next()
		read = itertools.islice(reader, length - 1)
		where.write(pfx + c + ''.join(read))
	    else:
		if c == ' ':
		    c = reader.next()
		if c == '\n':
		    read = []
		else:
		    read = itertools.takewhile(lambda c: c != '\n', reader)
		where.write(pfx + c + ''.join(read) + '\n')
	    where.flush()

	try:
	    while True:
		c = reader.next()
		if c == '?':
		    read_status()
		    return
		else:
		    read_output(c)
	except StopIteration:
	    raise EOFError()

    def run(self, cmd, stdin=None, stdout=None, stderr=None,
	    quote=True, prefix=None, error_prefix=None,
	    return_stdout=False):
	if return_stdout:
	    stdout = StringIO()
	    if prefix is None:
		prefix = ''
	if error_prefix is None:
	    error_prefix = prefix if prefix else self.error_prefix
	if prefix is None:
	    prefix = self.prefix
	if stdin is not None:
	    self.write_input(stdin)
	self.write_command(cmd, quote)
	self.read_result(stdout or sys.stdout, stderr or sys.stderr,
			 prefix, error_prefix)
	if return_stdout:
	    return stdout.getvalue().strip()


def run(exxes, cmd, stdout=None, stderr=None, quote=True, catch=False):
    # FIXME: Refactor read_result() so that it can read from multiple servers
    # in parallel.
    if not stdout:
	stdout = sys.stdout
    if not stderr:
	stderr = sys.stderr
    failed = set()

    for exxe in exxes:
	try:
	    exxe.write_command(cmd, quote)
	except IOError, e:
	    if catch:
		stderr.write('%s%s failed' % (self.error_prefix, cmd[0]))
		failed.add(exxe)
	    else:
		raise

    for exxe in exxes:
	if exxe in failed:
	    continue
	try:
	    exxe.read_result(stdout, stderr, exxe.prefix, exxe.error_prefix)
	except CalledProcessError, e:
	    if catch:
		stderr.write('%s%s failed with status %s' %
			     (self.error_prefix, cmd[0], e.returncode))
	    else:
		raise

    return not failed


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

    exxe = Exxe(args.server, shell=True,
		timeout=int(float(args.timeout) * 1000) if args.timeout else None,
		prefix=args.prefix,
		error_prefix=args.error_prefix)

    try:
	if args.stdin:
	    stdin = sys.stdin
	else:
	    stdin = None
	if args.canonical_output:
	    stdout = StringIO()
	    stderr = StringIO()
	else:
	    stdout = None
	    stderr = None
	exxe.run(args.cmd, stdin=stdin, stdout=stdout, stderr=stderr,
		 quote=not args.no_quote)
	if args.canonical_output:
	    sys.stdout.write(stdout.getvalue())
	    sys.stdout.flush()
	    sys.stderr.write(stderr.getvalue())
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

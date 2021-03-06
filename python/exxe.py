#! /usr/bin/env python3

from __future__ import print_function

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
from io import StringIO

__all__ = ['Exxe', 'run']


class ProcessTimeoutError(CalledProcessError):
    def __init__(self, cmd):
        super(ProcessTimeoutError, self).__init__(-signal.SIGTERM, cmd)

    def __str__(self):
        return "Command '%s' timed out" % self.cmd


class Exxe(object):
    def __init__(self, server, shell=False, timeout=None, prefix=None, error_prefix=None):
        """
        Keyword arguments:
        server -- command that starts the exxe server
        shell -- start the server command in a shell
        timeout -- default command timeout
        prefix -- default prefix for output
        error_prefix -- default prefix for error output (defaults to prefix)
        """
        self.server = subprocess.Popen(server, shell=shell,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE)
        self.timeout = timeout
        self.prefix = prefix if prefix is not None else ''
        self.error_prefix = error_prefix if error_prefix is not None else self.prefix

    def write_input(self, stdin):
        for line in stdin:
            if sys.version_info.major > 2:
                line = bytes(line, "utf-8")
                l = len(line)
            else:
                l = len(line)

            eol = ''
            num_bytes = str(l)
            if line[-1] != '\n':
                eol = '\n'
            elif not re.match(r'[\000-\037\200-\377]', line):
                num_bytes = ''
            if sys.version_info.major > 2:
                out = "<" + num_bytes + " " + line.decode("utf-8") + eol
                out = out.encode("utf-8")
            else:
                out = "<" + num_bytes + " " + line + eol
            #print("### %s ###" % out)
            os.write(self.server.stdin.fileno(), out)

    def write_command(self, cmd, quote):
        if isinstance(cmd, (str, bytes)):
            cmd = [cmd]
        cmd = ' '.join([pipes.quote(arg) for arg in cmd] if quote else cmd)
        self.cmd = cmd
        out = ('! ' + cmd + '\n')
        #print("#### %s ####" % out)
        if sys.version_info.major > 2:
            out = os.fsencode(out)
        os.write(self.server.stdin.fileno(), out)

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
                    data = bytes(os.read(self.server.stdout.fileno(), 128*1024))
                    if not data:
                        raise StopIteration()
                    #print(">>> data(%u): %s <<<" % (len(data), data), file=sys.stderr)
                    idx = 0
                if sys.version_info.major > 2:
                    #print(">>> b'\\x%02x' %c [%u/%u]<<<" % (data[idx], data[idx], idx, len(data)), file=sys.stderr)
                    yield bytes([data[idx]])
                else:
                    #print(">>> b'\\x%02x' %c [%u/%u]<<<" % (ord(data[idx]), data[idx], idx, len(data)), file=sys.stderr)
                    yield data[idx]
                idx += 1
        reader = reader_generator()

        def read_number(c):
            number = 0
            while c >= b'0' and c <= b'9':
                number = (10 * number) + ord(c) - ord('0')
                c = next(reader)
            return c, number

        def read_status():
            # From the itertools documentation:
            def consume(iterator):
                # feed the entire iterator into a zero-length deque
                collections.deque(iterator, maxlen=0)

            c = next(reader)
            if c == b' ':
                c = next(reader)
            if c == b'(':
                c, signal = read_number(next(reader))
                if c != b')':
                    raise IOError('Parsing exxe output ")" - have %s %s' % (c, signal))
                consume(itertools.takewhile(lambda c: c != b'\n', reader))
                raise CalledProcessError(-signal, self.cmd)
            else:
                c, status = read_number(c)
                if status == 0:
                    if c != b'\n':
                        raise IOError('Parsing exxe output "\\n"')
                else:
                    raise CalledProcessError(status, self.cmd)

        def read_output(c):
            # print(type(c), file=sys.stderr)
            # print(">>>> %s <<<<" % c, file=sys.stderr)
            if c == b'2':
                where = stderr
                pfx = error_prefix
                c = next(reader)
            else:
                where = stdout
                pfx = prefix
            if c != b'>':
                raise IOError('Parsing exxe output ">" - where %s, pfx %s, c %s' % (where, pfx, c))
            c = next(reader)
            if c >= b'0' and c <= b'9':
                c, length = read_number(c)
                if c == b' ':
                    c = next(reader)
                read = [c]
                read[1:] = itertools.islice(reader, length - 1)
                where.write((pfx.encode() + b''.join(read)).decode("utf-8"))
            else:
                if c == b' ':
                    c = next(reader)
                read = [c]
                if c != b'\n':
                    read[1:] = itertools.takewhile(lambda c: c != b'\n', reader)
                where.write((pfx.encode() + b''.join(read) + b'\n').decode("utf-8"))
            where.flush()

        try:
            while True:
                c = next(reader)
                # print(">>>> %s" % c, file=sys.stderr)
                while c == b' ' or c == b'\t' or c == b'\n':
                    c = next(reader)
                if c == b'?':
                    read_status()
                    return
                else:
                    read_output(c)
        except StopIteration:
            raise EOFError()

    def run(self, cmd, stdin=None, stdout=None, stderr=None,
            quote=True, prefix=None, error_prefix=None,
            return_stdout=False):
        """
        Run command cmd (a list of strings).  Raises CalledProcessError if cmd
        terminates with a non-zero exit status, and ProcessTimeoutError if the
        command times out.

        Keyword arguments:
        stdin -- standard input to command (file)
        stdout -- standard output from command (file)
        stderr -- standard error output from command (file)
        quote -- use shell quoting to prevent environment variable substitution in commands
        prefix -- override default prefix (see __init__)
        error_prefix -- override default error_prefix (see __init__)
        return_stdout -- if true, return standard output instead (strips leading / trailing whitespace)
        """
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
    """
    Run a command on multiple Exxe instances.

    Keyword arguments:
    catch -- When true, report command failures on stderr.  Returns False when
    a command has failed.
    """

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
        except IOError as e:
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
        except CalledProcessError as e:
            if catch:
                stderr.write('%s%s failed with status %s' %
                             (exxe.error_prefix, cmd[0], e.returncode))
            else:
                raise

    return not failed


if __name__ == '__main__':
    import argparse

    # To properly propagate the died-by-signal status,
    # if the command we called via exxe died by signal,
    # we re-raise that same signal here, to our whole process group.
    # To not kill "too many" in that case, including potentially our parent
    # shell, we setpgid() first.
    os.setpgid(0,0)

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
    except ProcessTimeoutError as error:
        print(error, file=sys.stderr)
        sys.exit(128 - error.returncode)
    except CalledProcessError as error:
        if error.returncode < 0:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            os.kill(0, -error.returncode)
        else:
            sys.exit(error.returncode)

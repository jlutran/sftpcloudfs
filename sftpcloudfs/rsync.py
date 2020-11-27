#!/usr/bin/python

import fcntl
import optparse
import os
import re
import select
import socket
import threading

from subprocess import Popen, PIPE


class RsyncException(Exception):
    def __init__(self, status, message, opts=None):
        self.status = status
        self.message = message
        self.opts = opts
        super(Exception, self).__init__(message)


class RsyncHandler(threading.Thread):

    TIMEOUT = 30.0  # seconds
    IN_SIZE = 2**19  # 512KB
    OPTIONS = [
        '--server',
        '--sender',
        '--delete',
        '--inplace',
        '--log-format=X',
        '--partial',
    ]
    OPTS_REGEX = r"^-[egiloprtv.DW]+LsfxC$"
    DOC_URL = "https://docs.ovh.com/gb/en/storage/pca/rsync"


    def __init__(self, rsync_bin, arguments, channel, fs, log, split_size):
        super(RsyncHandler, self).__init__()
        self.rsync_bin = rsync_bin
        self.args = arguments
        self.channel = channel
        self.channel.settimeout(self.TIMEOUT)
        self.fs = fs
        self.log = log
        self.split_size = str(split_size)

    def validate_args(self, args):
        args = [arg for arg in args if arg not in self.OPTIONS]
        args = [arg for arg in args if not re.match(self.OPTS_REGEX, arg)]
        if args:
            raise RsyncException(1, "Unsupported argument:", args)

    def run(self):
        try:
            self.log.debug("Rsync args %r", self.args)
            # Don't parse local and remote directories from self.args
            self.validate_args(self.args[:-2])
            self.rsync()
        except RsyncException as ex:
            self.log.exception("Rsync reject: %s", ex)
            self.send_status_and_close(msg=ex.message, status=ex.status, args=ex.opts)
        except socket.timeout:
            self.log.exception("Rsync timeout")
            self.send_status_and_close(msg="%ss timeout" % self.TIMEOUT, status=1)
        except:
            self.log.exception("Rsync internal exception")
            self.send_status_and_close(msg="internal error", status=1)
        else:
            self.send_status_and_close()

    def send_status_and_close(self, msg=None, status=0, args=None):
        try:
            if msg:
                self.print_to_stderr(msg, args)
            self.channel.send_exit_status(status)
        except socket.error, ex:
            self.log.warn("Failed to properly close the channel: %r" % ex.message)
        finally:
            try:
                self.channel.close()
            except socket.error:
                pass

    def print_to_stderr(self, msg, args):
        if args:
            m = '\n'.join(["[ERROR] %s %s" % (msg, arg) for arg in args])
        else:
            m = "[ERROR] %s" % msg
        m += "\n\nPlease check the documentation: %s\n\n" % self.DOC_URL
        self.channel.sendall_stderr(m)

    def rsync(self):
        path = self.args[-1]
        # Keep backward compatibility with svfs
        if path.startswith('/containers/'):
            path = path[len('/containers'):]
        path = os.path.normpath(path)
        prefix = ''
        if os.path.dirname(path) == os.sep:
            container = path.strip(os.sep)
        else:
            # Handle user@host:container path style
            if not path.startswith(os.sep):
                path = os.sep + path
            path = path.split(os.sep)
            container = path[1]
            prefix = "/".join(path[2:])

        # Container creation is not allowed
        if not self.fs.isdir(container):
            raise RsyncException(1, 'Invalid or non-existent container: %s' % container)

        # Cleanup dest path since it will be handleled internally by rsync
        if '--sender' in self.args:
            self.log.debug("Downloading from %s container" % container)
            self.args[-1] = os.sep + container
        else:
            self.log.debug("Uploading to %s container" % container)
            self.args[-1] = os.sep

        # Add swift-related options to rsync server command
        cmd = [
            self.rsync_bin, '-rW', '--inplace',
            '--os-swift', '1',
            '--os-auth-token', self.fs.conn.token,
            '--os-storage-url', self.fs.conn.url,
            '--os-segment-size', self.split_size,
            '--os-client-ip', self.fs.conn.real_ip,
            '--os-container', container,
        ]

        if prefix:
            cmd += ['--os-object-prefix', prefix]

        cmd += self.args
        self.log.debug("Rsync command: %s" % cmd)

        try:
            proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False)

            # Set non-blocking output
            output = proc.stdout
            fd = output.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

            # Loop until rsync process is done
            while proc.poll() is None:
                r, w, e = select.select([self.channel, output], [], [])
                if output in r:
                    buf = output.read()
                    self.channel.sendall(buf)
                if self.channel in r:
                    buf = self.channel.recv(self.IN_SIZE)
                    if len(buf):
                        proc.stdin.write(buf)
                        proc.stdin.flush()
        except Exception as e:
            raise RsyncException(1, 'Failed to execute rsync command: %s' % e)

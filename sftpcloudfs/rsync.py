#!/usr/bin/python

import fcntl
import optparse
import os
import select
import socket
import threading

from subprocess import Popen, PIPE

from ftpcloudfs.fs import IOSError, parse_fspath

class RsyncException(Exception):
    def __init__(self, status, message):
        self.status = status
        super(Exception, self).__init__(message)


class RsyncHandler(threading.Thread):

    TIMEOUT = 30.0 # seconds
    IN_SIZE = 2**19 # 512KB

    def __init__(self, rsync_bin, arguments, channel, fs, log, split_size):
        super(RsyncHandler, self).__init__()
        self.rsync_bin = rsync_bin
        self.args = arguments
        self.channel = channel
        self.channel.settimeout(self.TIMEOUT)
        self.fs = fs
        self.log = log
        self.split_size = str(split_size)

    @classmethod
    def get_argparser(cls):
        parser = optparse.OptionParser(
            prog='rsync',
            description='A fast, versatile, remote (and local) file-copying tool',
        )
        parser.add_option('--server', action='store_true', dest='mode')
        parser.add_option('--daemon', action='store_true', dest='daemon')
        parser.add_option('--sender', action='store_true', dest='sender')
        parser.add_option('--inplace', action='store_true', dest='inplace')
        parser.add_option('-W', action='store_true', dest='whole_files')
        parser.add_option('-v', action='count', dest='verbose',
                          help='makes Rsync verbose')
        parser.add_option('-t', action='store_true', dest='copy_to')
        parser.add_option('-f', action='store_true', dest='copy_from')
        parser.add_option('-r', action='store_true', dest='recursive',
                          help='Recursively copy entire directories.')
        parser.add_option('-e', action='store_true', dest='remote_shell')
        parser.add_option('-i', action='store_true', dest='i')
        parser.add_option('-L', action='store_true', dest='L')
        parser.add_option('-s', action='store_true', dest='s')
        parser.add_option('-x', action='store_true', dest='x')
        parser.add_option('-C', action='store_true', dest='C')
        parser.add_option('-.', action='store_true', dest='dot')

        def ap_exit(status=0, message=""):
            raise RsyncException(status, message)

        parser.exit = ap_exit
        parser.error = lambda msg: ap_exit(2, msg)

        return parser

    def run(self):
        try:
            self.log.debug("Rsync args %r", self.args)
            if '--daemon' in self.args:
                raise RsyncException(4, "Daemon mode is not supported")
            if '--server' in self.args:
                path = self.args[-1]
                self.rsync(path)
            else:
                raise RsyncException(4, "Unsupported arguments list: %s" % self.args)
        except RsyncException, ex:
            self.log.info("Rsync reject: %s", ex)
            self.send_status_and_close(msg=ex, status=ex.status)
        except socket.timeout:
            self.log.info("Rsync timeout")
            self.send_status_and_close(msg="%ss timeout" % self.TIMEOUT, status=1)
        except:
            self.log.exception("Rsync internal exception")
            self.send_status_and_close(msg="internal error", status=1)
        else:
            self.send_status_and_close()

    def send_status_and_close(self, msg=None, status=0):
        try:
            self.channel.send_exit_status(status)
        except socket.error, ex:
            self.log.warn("Failed to properly close the channel: %r" % ex.message)
        finally:
            try:
                self.channel.close()
            except socket.error:
                pass

    def rsync(self, path):
        path = os.path.normpath(path)
        prefix = ''
        if os.path.dirname(path) == os.sep:
            container = path.strip(os.sep)
        else:
            path = path.split(os.sep)
            container = path[1]
            prefix = "/".join(path[2:])

        # Container creation is not allowed
        if not self.fs.isdir(container):
            raise RsyncException(1, '%s is not a valid container name' % container)

        # Cleanup dest path since it will be handleled internally by rsync
        if '--sender' in self.args:
            self.log.info("Downloading from %s container" % container)
            self.args[-1] = os.sep + container
        else:
            self.log.info("Uploading to %s container" % container)
            self.args[-1] = os.sep

        # Add swift-related options to rsync server command
        cmd = [
            self.rsync_bin,
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
        self.log.info("Rsync command: %s" % cmd)

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

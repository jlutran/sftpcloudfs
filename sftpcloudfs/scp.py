#!/usr/bin/python
"""
SCP support.

Copyright (C) 2011-2019 by Memset Ltd. http://www.memset.com/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

import stat
import optparse
import posixpath
import socket
import threading

from ftpcloudfs.fs import IOSError, parse_fspath

class SCPException(Exception):
    def __init__(self, status, message):
        self.status = status
        super(Exception, self).__init__(message)


class SCPHandler(threading.Thread):

    CHUNK_SIZE = 64*1024
    TIMEOUT = 30.0 # seconds

    def __init__(self, arguments, channel, fs, log):
        super(SCPHandler, self).__init__()
        self.log = log
        self.channel = channel
        self.channel.settimeout(self.TIMEOUT)
        self.fs = fs
        self.args = arguments
        self.buffer = ""

    @classmethod
    def get_argparser(cls):
        parser = optparse.OptionParser(
            prog='scp',
            description='Remote part of secure copy tool'
        )
        parser.add_option('-v', action='count', dest='verbose',
                          help='makes SCP verbose')
        parser.add_option('-t', action='store_true', dest='copy_to')
        parser.add_option('-f', action='store_true', dest='copy_from')
        parser.add_option('-r', action='store_true', dest='recursive',
                          help='Recursively copy entire directories.')
        # unused
        parser.add_option('-p', action='store_true', dest='preserve',
                          help='Preserves modification times, access '
                               'times, and modes from the original file.')
        parser.add_option('-d', action='store_true', dest='directory',
                          help='Target should be a directory')
        parser.add_option('-E', action='store_true', dest='xargs',
                          help='Target should be a directory')

        def ap_exit(status=0, message=""):
            raise SCPException(status, message)

        parser.exit = ap_exit
        parser.error = lambda msg: ap_exit(2, msg)

        return parser

    def run(self):
        try:
            self.args, self.paths = SCPHandler.get_argparser().parse_args(self.args)
            self.log.debug("SCP %r", self.args)

            if self.args.copy_to and self.args.copy_from:
                raise SCPException(4, "-t and -f can't be combined")

            if len(self.paths) != 1:
                raise SCPException(4, "scp takes exactly one path")

            if self.args.copy_to:
                self.receive()
            elif self.args.copy_from:
                path = self.paths[0]
                try:
                    path_stat = self.fs.stat(path)
                except IOSError, ex:
                    raise SCPException(1, ex)

                self.send(path, path_stat)
            else:
                raise SCPException(4, "Missing -t or -f argument")
        except SCPException, ex:
            self.log.info("SCP reject: %s", ex)
            self.send_status_and_close(msg=ex, status=ex.status)
        except socket.timeout:
            self.log.info("SCP timeout")
            self.send_status_and_close(msg="%ss timeout" % self.TIMEOUT, status=1)
        except:
            self.log.exception("SCP internal exception")
            self.send_status_and_close(msg="internal error", status=1)
        else:
            self.send_status_and_close()

    def send_status_and_close(self, msg=None, status=0):
        try:
            if msg:
                self.channel.sendall('\x01scp: ')
                self.channel.sendall(str(msg))
                self.channel.sendall('\n')
            self.channel.send_exit_status(status)
        except socket.error, ex:
            self.log.warn("Failed to properly close the channel: %r" % ex.message)
        finally:
            try:
                self.channel.close()
            except socket.error:
                pass

    def recv(self, size):
        if self.buffer:
            result = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return result

        return self.channel.recv(size)

    def recv_line(self):
        if '\n' not in self.buffer:
            while True:
                chunk = self.channel.recv(1024)
                if not chunk:
                    return self.buffer
                if chunk.startswith('\x00'):
                    chunk = chunk[1:]
                self.buffer += chunk
                if '\n' in chunk:
                    break

        line, self.buffer = self.buffer.split('\n', 1)
        return line

    def receive(self):
        if not self.args.directory and not self.args.recursive:
            directory, filename = posixpath.split(self.paths[0])
        else:
            directory = self.paths[0]
            filename = None

        # Handle user@host:container path style
        if not directory.startswith('/'):
            directory = '/' + directory
        # Keep backward compatibility with svfs
        elif directory.startswith('/containers/'):
            directory = directory[len('/containers'):]

        if not self.fs.isdir(directory):
            raise SCPException(1, '%s is not a directory' % directory)

        self.recv_files(directory)
        self.send_status_and_close()

    def recv_dir(self, path):
        self.fs.mkdir(path)
        self.recv_files(path)

    def recv_file(self, path, size):
        self.channel.send('\x00')

        try:
            size = int(size)
        except ValueError:
            raise SCPException(1, 'invalid size')

        fd = self.fs.open(path, 'w')

        bytes_sent = 0
        while bytes_sent < size:
            blocklen = min(size - bytes_sent, self.CHUNK_SIZE)
            chunk = self.recv(blocklen)
            fd.write(chunk)
            bytes_sent += len(chunk)

        fd.close()
        self.channel.send('\x00')

    def recv_files(self, path):
        self.channel.send('\x00')
        while True:
            record = self.recv_line()
            if not record:
                break
            if record[0] == 'T':
                self.channel.send('\x00')
            elif record[0] == 'E':
                self.channel.send('\x00')
                break
            elif record[0] in 'CD':
                mode, size, name = record[1:].split(' ', 2)
                _path = posixpath.join(path, name)

                if record[0] == 'D':
                    self.recv_dir(_path)
                else:
                    # we can't create files on the root, only inside a container
                    if not all(parse_fspath(_path)):
                        raise SCPException(1, "%s: container required" % _path)
                    self.recv_file(_path, size)
            else:
                raise SCPException(1, 'Unknown request: %s' % record)

    def send(self, path, path_stat):
        self.log.debug('About to send %s', path)

        if self.args.preserve:
            self.channel.sendall("T%i 0 %i 0\n" % (
                                 path_stat.st_mtime,
                                 path_stat.st_atime))
            self.wait_for_ack()

        if stat.S_ISREG(path_stat.st_mode):
            self.channel.sendall("C%04o %i %s\n" % (
                                 path_stat.st_mode & 07777,
                                 path_stat.st_size,
                                 posixpath.basename(path)))
            self.wait_for_ack()

            fd = self.fs.open(path, 'r')
            while True:
                chunk = fd.read(self.CHUNK_SIZE)
                if chunk:
                    self.channel.sendall(chunk)
                else:
                    break

            # signal the end of the transfer
            self.channel.send('\x00')
            self.wait_for_ack()

        elif not self.args.recursive:
            self.channel.sendall("scp: %s is not a regular file\n" % path)
            return 1
        else:
            self.channel.send("D%04o %i %s\n" % (
                              path_stat.st_mode & 07777,
                              0,
                              posixpath.basename(path)))

            self.wait_for_ack()

            for subpath, subpath_stat in self.fs.listdir_with_stat(path):
                subpath = path + "/" + subpath
                self.send(subpath, subpath_stat)

            self.channel.send("E\n")
            self.wait_for_ack()

    def wait_for_ack(self):
        """ Wait for the ack byte """
        ack = self.channel.recv(1)
        if ack != '\x00':
            raise Exception("Command not acknowledged (%r)" % ack)


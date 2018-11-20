#!/usr/bin/env python3

"""
    A pure python ping implementation using raw socket.


    Note that ICMP messages can only be sent from processes running as root.


    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependenceies here.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py

    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122

    Rewrite by George Notaras:
      -> http://www.g-loaded.eu/2009/10/30/python-ping/

    Fork by Pierre Bourdon:
      -> http://bitbucket.org/delroth/python-ping/

    Fork by Nick Cripps
      -> https://github.com/ArcolaEnergy/python-ping/

    Revision history
    ~~~~~~~~~~~~~~~~

    November 22, 1997
    -----------------
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.

    December 16, 1997
    -----------------
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().

    December 4, 2000
    ----------------
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.

    May 30, 2007
    ------------
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"

    November 8, 2009
    ----------------
    Improved compatibility with GNU/Linux systems.

    Fixes by:
     * George Notaras -- http://www.g-loaded.eu
    Reported by:
     * Chris Hallman -- http://cdhallman.blogspot.com

    Changes in this release:
     - Re-use time.time() instead of time.clock(). The 2007 implementation
       worked only under Microsoft Windows. Failed on GNU/Linux.
       time.clock() behaves differently under the two OSes[1].

    [1] http://docs.python.org/library/time.html#time.clock

    September 25, 2010
    ------------------
    Little modifications by Georgi Kolev:
     -  Added quiet_ping function.
     -  returns percent lost packages, max round trip time, avrg round trip
        time
     -  Added packet size to verbose_ping & quiet_ping functions.
     -  Bump up version to 0.2

    November 19, 2018
    -----------------
    Converted to Python 3 using 2to3 from Python 3.6 with manual changes
    Bumped version to 0.3

    November 20, 2018
    -----------------
    Code style improvements

"""

__version__ = "0.3"

import os
import select
import socket
import struct
import time

# From /usr/include/linux/icmp.h; your mileage may vary.
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.


def checksum(source_bytes):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    chk_sum = 0
    count_to = (len(source_bytes) // 2) * 2
    for count in range(0, count_to, 2):
        this = source_bytes[count + 1] * 256 + source_bytes[count]
        chk_sum = chk_sum + this
        chk_sum = chk_sum & 0xffffffff  # Necessary?

    if count_to < len(source_bytes):
        chk_sum = chk_sum + source_bytes[len(source_bytes) - 1]
        chk_sum = chk_sum & 0xffffffff  # Necessary?

    chk_sum = (chk_sum >> 16) + (chk_sum & 0xffff)
    chk_sum = chk_sum + (chk_sum >> 16)
    answer = ~chk_sum
    answer = answer & 0xffff

    # Swap bytes.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def receive_one_ping(my_socket, packet_id, timeout):
    """
    Receive the ping from the socket.
    """
    time_left = timeout
    while True:
        started_select = time.time()
        what_ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = (time.time() - started_select)
        if what_ready[0] == []:  # Timeout
            return

        time_received = time.time()
        received_packet, addr = my_socket.recvfrom(1024)
        icmp_header = received_packet[20:28]
        icmp_type, code, checksum_field, received_packet_id, sequence = struct.unpack(
            "bbHHh", icmp_header
        )
        if received_packet_id == packet_id:
            n_bytes = struct.calcsize("d")
            time_sent = struct.unpack("d", received_packet[28:28 + n_bytes])[0]
            return time_received - time_sent

        time_left = time_left - how_long_in_select
        if time_left <= 0:
            return


def send_one_ping(my_socket, dest_addr, packet_id, packet_size):
    """
    Send one ping to the given >dest_addr<.
    """
    dest_addr = socket.gethostbyname(dest_addr)

    # Remove header size from packet size
    packet_size = packet_size - 8

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0

    # Make a dummy header with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, packet_id, 1)
    n_bytes = struct.calcsize("d")
    data = ((packet_size - n_bytes) * "Q").encode('ascii', errors='strict')
    data = struct.pack("d", time.time()) + data

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packet_id, 1
    )
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1


def do_one(dest_addr, timeout, packet_size):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error as socket_error:
        (errno, msg) = socket_error.args
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root or with CAP_NET_RAW."
            )
            raise socket.error(msg)
        raise  # raise the original error

    my_id = os.getpid() & 0xFFFF

    send_one_ping(my_socket, dest_addr, my_id, packet_size)
    delay = receive_one_ping(my_socket, my_id, timeout)

    my_socket.close()
    return delay


def verbose_ping(dest_addr, timeout=2, count=4, packet_size=64):
    """
    Send `count' ping with `packet_size' size to `dest_addr' with
    the given `timeout' and display the result.
    """
    for i in range(count):
        print("ping %s with ..." % dest_addr, end='')
        try:
            delay = do_one(dest_addr, timeout, packet_size)
        except socket.gaierror as e:
            print("failed. (socket error: '%s')" % str(e))
            break

        if delay is None:
            print("failed. (timeout within %ssec.)" % timeout)
        else:
            delay = delay * 1000
            print("get ping in %0.4fms" % delay)
    print()


def quiet_ping(dest_addr, timeout=2, count=4, packet_size=64):
    """
    Send `count' ping with `packet_size' size to `dest_addr' with
    the given `timeout' and display the result.
    Returns `percent' lost packages, `max' round trip time
    and `avrg' round trip time.
    """
    mrtt = None
    artt = None
    plist = []

    for i in range(count):
        try:
            delay = do_one(dest_addr, timeout, packet_size)
        except socket.gaierror as e:
            print("failed. (socket error: '%s')" % e[1])
            break

        if delay is not None:
            delay = delay * 1000
            plist.append(delay)

    # Find lost package percent
    percent_lost = 100 - (len(plist) * 100 / count)

    # Find max and avg round trip time
    if plist:
        mrtt = max(plist)
        artt = sum(plist) / len(plist)

    return percent_lost, mrtt, artt


if __name__ == '__main__':
    verbose_ping("heise.de")
    verbose_ping("google.com")
    verbose_ping("a-test-url-that-is-not-available.com")
    verbose_ping("192.168.1.1")

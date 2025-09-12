import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33433  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3


# Since bytes are in big endian, this works. Most significant byte us on left as required
def convert_bytes_to_int(b: str, start: int, len: int):
    return int(b[start * 8: (start + len) * 8], 2)

def make_address(b: str, start: int, len: int):
    return f"{convert_bytes_to_int(b, start, 1)}.{convert_bytes_to_int(b, start + 1, 1)}.{convert_bytes_to_int(b, start + 2, 1)}.{convert_bytes_to_int(b, start + 3, 1)}"

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        pass  # TODO
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = convert_bytes_to_int(b, 0, 1) >> 4
        self.header_len =  (convert_bytes_to_int(b, 0, 1) & 15) * 4  # since header_len is in terms of 4 bytes
        self.tos = convert_bytes_to_int(b, 1, 1)
        self.length = convert_bytes_to_int(b, 2, 2)
        self.id = convert_bytes_to_int(b, 4, 2)
        self.flags = convert_bytes_to_int(b, 6, 1) >> 5
        self.frag_offset = util.ntohs((convert_bytes_to_int(b, 6, 2) << 3) >> 3)
        self.ttl = convert_bytes_to_int(b, 8, 1)
        self.proto = convert_bytes_to_int(b, 9, 1)
        self.cksum = convert_bytes_to_int(b, 10, 2)
        self.src = make_address(b, 12, 4)
        self.dst = make_address(b, 16, 4)

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        pass  # TODO
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = convert_bytes_to_int(b, 0, 1)
        self.code = convert_bytes_to_int(b, 1, 1)
        self.cksum = convert_bytes_to_int(b, 2, 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        pass  # TODO
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = convert_bytes_to_int(b, 0, 2)
        self.dst_port = convert_bytes_to_int(b, 2, 2)
        self.len = convert_bytes_to_int(b, 4, 2)
        self.cksum = convert_bytes_to_int(b, 6, 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def check_ttl_expired(icmp: ICMP):
    return icmp.type == 11 and icmp.code == 0

def check_port_unreachable(icmp: ICMP):
    return icmp.type == 3 and icmp.code == 3

def recv_probe_res(recvsock: util.Socket, ip: str, ttl: int):
    while recvsock.recv_select():
        (packet, addr) = recvsock.recvfrom()
        ipv4 = IPv4(packet)

        # only parse icmp packets
        if ipv4.proto != 1:
            continue 

        if ipv4.length != len(packet):
            continue

        icmp = ICMP(packet[ipv4.header_len:])

        if not check_ttl_expired(icmp) and not check_port_unreachable(icmp):
            continue

        ipv4_send = IPv4(packet[ipv4.header_len + 8:])
        udp = UDP(packet[ipv4.header_len + 8 + ipv4_send.header_len:])

        if ipv4_send.dst != ip:
            continue

        # if true, it belongs to previous ttl probe. Probably got delayed.
        if udp.dst_port != TRACEROUTE_PORT_NUMBER + ttl:
            print("Here")
            continue

        # For duplicates drain
        if recvsock.recv_select():
            while recvsock.recv_select(): recvsock.recvfrom()
        
        return addr[0]

    return None


def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    discovered_routers = []
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        sendsock.set_ttl(ttl)
        routers = []
        for _ in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto(f"{ttl}".encode(), (ip, TRACEROUTE_PORT_NUMBER + ttl))
            addr = recv_probe_res(recvsock, ip, ttl)
            if addr is None or addr in routers:
                continue

            routers.append(addr)
            
        util.print_result(routers, ttl)
        discovered_routers.append(routers)

        if ip in routers:
            break

    return discovered_routers

    ## Stage 1
    # sendsock.set_ttl(7)
    # sendsock.sendto("Hi".encode(), (ip, TRACEROUTE_PORT_NUMBER + 7))
    # if recvsock.recv_select():
    #     buf, addr = recvsock.recvfrom()
    #     print(f"Packet bytes: {buf.hex()}") 
    #     print(IPv4(buf[0:20]))
    #     print(ICMP(buf[20:28]))
    #     print(IPv4(buf[28:48]))
    #     print(UDP(buf[48:58]))


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

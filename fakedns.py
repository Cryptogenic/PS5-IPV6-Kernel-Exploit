#!/usr/bin/env python
"""Fakedns.py: A regular-expression based DNS MITM Server by Crypt0s."""

# This isn't the most elegent way - i could possibly support both versions of python,
# but people should really not use Python 2 anymore.
import sys
vnum = sys.version.split()[0]
if int(vnum[0]) < 3:
    print("Python 2 support has been deprecated.  Please run FakeDNS using Python3!")
    sys.exit(1)

import binascii
import socket
import re
import sys
import os
import socketserver as SocketServer
import signal
import argparse
import struct
import random
import configparser as ConfigParser

# inspired from DNSChef
class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, server_address, request_handler):
        self.address_family = socket.AF_INET
        SocketServer.UDPServer.__init__(
            self, server_address, request_handler)


class UDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        (data, s) = self.request
        respond(data, self.client_address, s)


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = b''
        tipo = (data[2] >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += data[ini + 1:ini + lon + 1] + b'.'
                ini += lon + 1  # you can implement CNAME and PTR
                lon = data[ini]
            self.type = data[ini:][1:3]
        else:
            self.type = data[-4:-2]

# Because python doesn't have native ENUM in 2.7:
# https://en.wikipedia.org/wiki/List_of_DNS_record_types
TYPE = {
    b"\x00\x01": "A",
    b"\x00\x1c": "AAAA",
    b"\x00\x05": "CNAME",
    b"\x00\x0c": "PTR",
    b"\x00\x10": "TXT",
    b"\x00\x0f": "MX",
    b"\x00\x06": "SOA"
}

# Stolen:
# https://github.com/learningequality/ka-lite/blob/master/python-packages/django/utils/ipv6.py#L209
def _is_shorthand_ip(ip_str):
    """Determine if the address is shortened.
    Args:
        ip_str: A string, the IPv6 address.
    Returns:
        A boolean, True if the address is shortened.
    """
    if ip_str.count('::') == 1:
        return True
    if any(len(x) < 4 for x in ip_str.split(':')):
        return True
    return False

# Stolen:
# https://github.com/learningequality/ka-lite/blob/master/python-packages/django/utils/ipv6.py#L209
def _explode_shorthand_ip_string(ip_str):
    """
    Expand a shortened IPv6 address.
    Args:
        ip_str: A string, the IPv6 address.
    Returns:
        A string, the expanded IPv6 address.
    """
    if not _is_shorthand_ip(ip_str):
        # We've already got a longhand ip_str.
        return ip_str

    hextet = ip_str.split('::')

    # If there is a ::, we need to expand it with zeroes
    # to get to 8 hextets - unless there is a dot in the last hextet,
    # meaning we're doing v4-mapping
    if '.' in ip_str.split(':')[-1]:
        fill_to = 7
    else:
        fill_to = 8

    if len(hextet) > 1:
        sep = len(hextet[0].split(':')) + len(hextet[1].split(':'))
        new_ip = hextet[0].split(':')

        for _ in range(fill_to - sep):
            new_ip.append('0000')
        new_ip += hextet[1].split(':')

    else:
        new_ip = ip_str.split(':')

    # Now need to make sure every hextet is 4 lower case characters.
    # If a hextet is < 4 characters, we've got missing leading 0's.
    ret_ip = []
    for hextet in new_ip:
        ret_ip.append(('0' * (4 - len(hextet)) + hextet).lower())
    return ':'.join(ret_ip)


def _get_question_section(query):
    # Query format is as follows: 12 byte header, question section (comprised
    # of arbitrary-length name, 2 byte type, 2 byte class), followed by an
    # additional section sometimes. (e.g. OPT record for DNSSEC)
    start_idx = 12
    end_idx = start_idx

    num_questions = (query.data[4] << 8) | query.data[5]

    while num_questions > 0:
        while query.data[end_idx] != 0:
            end_idx += query.data[end_idx] + 1
        # Include the null byte, type, and class
        end_idx += 5
        num_questions -= 1

    return query.data[start_idx:end_idx]


class DNSFlag:
    # qr  opcode   aa   tc  rd  ra  z    rcode
    # 1   0000     0    0   1   1   000  0000
    # accept a series of kwargs to build a proper flags segment.
    def __init__(self,
                qr=0b1,        # query record, 1 if response
                opcode=0b0000, # 0 = query, 1 = inverse query, 2 = status request 3-15 unused
                aa=0b0,        # authoritative answer = 1
                tc=0b0,        # truncation - 1 if truncated
                rd=0b1,        # recursion desired?
                ra=0b1,        # recursion available
                z=0b000,       # Reserved, must be zero in queries and responsed
                rcode=0b0000   # errcode, 0 none, 1 format, 2 server, 3 name, 4 not impl, 5 refused, 6-15 unused
                 ):

        # pack the elements into an integer
        flag_field = qr
        flag_field = flag_field << 4
        flag_field ^= opcode
        flag_field = flag_field << 1
        flag_field ^= aa
        flag_field = flag_field << 1
        flag_field ^= tc
        flag_field = flag_field << 1
        flag_field ^= rd
        flag_field = flag_field << 1
        flag_field ^= ra
        flag_field = flag_field << 3
        flag_field ^= z
        flag_field = flag_field << 4
        flag_field ^= rcode

        self.flag_field = flag_field

    # return char rep.
    def pack(self):
        return struct.pack(">H", self.flag_field)


class DNSResponse(object):
    def __init__(self, query):
        self.id = query.data[:2]  # Use the ID from the request.
        self.flags = DNSFlag(aa=args.authoritative).pack()
        self.questions = query.data[4:6]  # Number of questions asked...
        # Answer RRs (Answer resource records contained in response) 1 for now.
        self.rranswers = b"\x00\x01"
        self.rrauthority = b"\x00\x00"  # Same but for authority
        self.rradditional = b"\x00\x00"  # Same but for additionals.
        # Include the question section
        self.query = _get_question_section(query)
        # The pointer to the resource record - seems to always be this value.
        self.pointer = b"\xc0\x0c"
        # This value is set by the subclass and is defined in TYPE dict.
        self.type = None
        self.dnsclass = b"\x00\x01"  # "IN" class.
        # TODO: Make this adjustable - 1 is good for noobs/testers
        self.ttl = b"\x00\x00\x00\x01"
        # Set by subclass because is variable except in A/AAAA records.
        self.length = None
        self.data = None  # Same as above.

    def make_packet(self):
        try:
            return self.id + self.flags + self.questions + self.rranswers + \
                self.rrauthority + self.rradditional + self.query + \
                self.pointer + self.type + self.dnsclass + self.ttl + \
                self.length + self.data
        except Exception as e: #(TypeError, ValueError):
            print("[!] - %s" % str(e))

# All classes need to set type, length, and data fields of the DNS Response
# Finished
class A(DNSResponse):
    def __init__(self, query, record):
        super(A, self).__init__(query)
        self.type = b"\x00\x01"
        self.length = b"\x00\x04"
        self.data = self.get_ip(record)

    @staticmethod
    def get_ip(dns_record):
        ip = dns_record
        # Convert to hex
        return b''.join(int(x).to_bytes(1, 'little') for x in ip.split('.'))

# Implemented
class AAAA(DNSResponse):
    def __init__(self, query, address):
        super(AAAA, self).__init__(query)
        self.type = b"\x00\x1c"
        self.length = b"\x00\x10"
        # Address is already encoded properly for the response at rule-builder
        self.data = address

    # Thanks, stackexchange!
    # http://stackoverflow.com/questions/16276913/reliably-get-ipv6-address-in-python
    def get_ip_6(host, port=0):
        # search only for the wanted v6 addresses
        result = socket.getaddrinfo(host, port, socket.AF_INET6)
        # Will need something that looks like this:
        # just returns the first answer and only the address
        ip = result[0][4][0]

# Implemented
class CNAME(DNSResponse):
    def __init__(self, query, domain):
        super(CNAME, self).__init__(query)
        self.type = b"\x00\x05"

        self.data = b""
        for label in domain.split('.'):
            self.data += chr(len(label)).encode() + label.encode()
        self.data += b"\x00"

        self.length = chr(len(self.data)).encode()
        # Must be two bytes.
        if len(self.length) < 2:
            self.length = b"\x00" + self.length

# Implemented
class PTR(DNSResponse):
    def __init__(self, query, ptr_entry):
        super(PTR, self).__init__(query)
        if type(ptr_entry) != bytes:
            ptr_entry = ptr_entry.encode()

        self.type = b"\x00\x0c"
        self.ttl = b"\x00\x00\x00\x00"
        ptr_split = ptr_entry.split(b'.')
        ptr_entry = b"\x07".join(ptr_split)

        self.data = b"\x09" + ptr_entry + b"\x00"
        self.length = chr(len(ptr_entry) + 2)
        # Again, must be 2-byte value.
        if self.length < "0xff":
            self.length = b"\x00" + self.length.encode()

# Finished
class TXT(DNSResponse):
    def __init__(self, query, txt_record):
        super(TXT, self).__init__(query)
        self.type = b"\x00\x10"
        self.data = txt_record.encode()
        self.length = chr(len(txt_record) + 1).encode()
        # Must be two bytes.  This is the better, more python-3 way to calculate length.  Swap to this later.
        if len(self.length) < 2:
            self.length = b"\x00" + self.length 
        # Then, we have to add the TXT record length field!  We utilize the
        # length field for this since it is already in the right spot
        self.length += chr(len(txt_record)).encode()


class MX(DNSResponse):
    def __init__(self, query, txt_record):
        super(MX, self).__init__(query)
        self.type = b"\x00\x0f"
        self.data = b"\x00\x01" + self.get_domain(txt_record) + b"\x00"
        self.length = chr(len(txt_record) + 4)
        if self.length < '\xff':
            self.length = "\x00" + self.length

    @staticmethod
    def get_domain(dns_record):
       domain = dns_record
       ret_domain=[]
       for x in domain.split('.'):
               st = "{:02x}".format(len(x))
               ret_domain.append( st.decode("hex"))
               ret_domain.append(x)
       return "".join(ret_domain)

class SOA(DNSResponse):
    def __init__(self, query, config_location):
        super(SOA, self).__init__(query)

        # TODO: pre-read and cache all the config files for the rules for speed.
        config = ConfigParser.ConfigParser(inline_comment_prefixes=";")
        config.read(config_location)

        # handle cases where we want the serial to be random
        serial = config.get(query.domain.decode(), "serial")
        if serial.lower() == "random":
            serial = int(random.getrandbits(32))
        else:
            # serial is still a str, cast to int.
            serial = int(serial)

        self.type = b"\x00\x06"
        self.mname = config.get(query.domain.decode(), "mname")       # name server that was original or primary source for this zone
        self.rname = config.get(query.domain.decode(), "rname")       # domain name which specified mailbox of person responsible for zone
        self.serial = serial                                 # 32-bit long version number of the zone copy
        self.refresh = config.getint(query.domain.decode(), "refresh")# 32-bit time interval before zone refresh
        self.retry = config.getint(query.domain.decode(), "retry")    # 32-bit time interval before retrying failed refresh
        self.expire = config.getint(query.domain.decode(), "expire")  # 32-bit time interval after which the zone is not authoritative
        self.minimum = config.getint(query.domain.decode(), "minimum")# The unsigned 32 bit minimum TTL for any RR from this zone.

        # convert the config entries into DNS format. Convenient conversion function will be moved up to module later.
        def convert(fqdn):
            tmp = b""
            for domain in fqdn.split('.'):
                tmp += chr(len(domain)).encode() + domain.encode()
            tmp += b"\xc0\x0c"
            return tmp

        self.data = b""

        self.mname = convert(self.mname)
        self.data += self.mname

        self.rname = convert(self.rname)
        self.data += self.rname # already is a bytes object.

        # pack the rest of the structure
        self.data += struct.pack('>I', self.serial)
        self.data += struct.pack('>I', self.refresh)
        self.data += struct.pack('>I', self.retry)
        self.data += struct.pack('>I', self.refresh)
        self.data += struct.pack('>I', self.minimum)

        # get length of the answers area
        self.length = chr(len(self.data))

        # length is always two bytes - add the extra blank byte if we're not large enough for two bytes.
        if self.length < "0xff":
            self.length = b"\x00" + self.length.encode()



# And this one is because Python doesn't have Case/Switch
CASE = {
    b"\x00\x01": A,
    b"\x00\x1c": AAAA,
    b"\x00\x05": CNAME,
    b"\x00\x0c": PTR,
    b"\x00\x10": TXT,
    b"\x00\x0f": MX,
    b"\x00\x06": SOA,
}

# Technically this is a subclass of A
class NONEFOUND(DNSResponse):
    def __init__(self, query):
        super(NONEFOUND, self).__init__(query)
        self.type = query.type
        self.flags = b"\x81\x83"
        self.rranswers = b"\x00\x00"
        self.length = b"\x00\x00"
        self.data = b"\x00"
        print(">> Built NONEFOUND response")


class Rule (object):
    def __init__(self, rule_type, domain, ips, rebinds, threshold):
        self.type = rule_type
        self.domain = domain
        self.ips = ips
        self.rebinds = rebinds
        self.rebind_threshold = threshold

        # we need an additional object to track the rebind rules
        if self.rebinds is not None:
            self.match_history = {}
            self.rebinds = self._round_robin(rebinds)
        self.ips = self._round_robin(ips)

    def _round_robin(self, ip_list):
        """
        Creates a generator over a list modulo list length to equally move between all elements in the list each request
        Since we have rules broken out into objects now, we can have this without much overhead.
        """
        # check to make sure we don't try to modulo by zero
        # if we would, just add the same element to the list again.
        if len(ip_list) == 1:
            ip_list.append(ip_list[0])

        # should be fine to continue now.
        index = 0
        while 1: # never stop iterating - it's OK since we dont always run
            yield ip_list[index]
            index += 1
            index = index % len(ip_list)

    def match(self, req_type, domain, addr):
        # assert that the query type and domain match
        try:
            req_type = TYPE[req_type]
        except KeyError:
            return None

        try:
            assert self.type == req_type
        except AssertionError:
            return None

        try:
            assert self.domain.match(domain.decode())
        except AssertionError:
            return None

        # Check to see if we have a rebind rule and if we do, return that addr first
        if self.rebinds:
            if self.match_history.get(addr) is not None:

                # passed the threshold - start doing a rebind
                if self.match_history[addr] >= self.rebind_threshold:
                    return next(self.rebinds)

                # plus one
                else:
                    self.match_history[addr] += 1

            # add new client to this match history
            else:
                self.match_history[addr] = 1

        # We didn't trip on any rebind rules (or didnt have any)
        # but we're returning a rule-based entry based on the match
        return next(self.ips)


# Error classes for handling rule issues
class RuleError_BadRegularExpression(Exception):
    def __init__(self,lineno):
        print("\n!! Malformed Regular Expression on rulefile line #%d\n\n" % lineno)


class RuleError_BadRuleType(Exception):
    def __init__(self,lineno):
        print("\n!! Rule type unsupported on rulefile line #%d\n\n" % lineno)


class RuleError_BadFormat(Exception):
    def __init__(self,lineno):
        print("\n!! Not Enough Parameters for rule on rulefile line #%d\n\n" % lineno)


class RuleEngine2:

    # replaces the self keyword, but could be expanded to any keyword replacement
    def _replace_self(self, ips):
        # Deal with the user putting "self" in a rule (helpful if you don't know your IP)
        for ip in ips:
            if ip.lower() == 'self':
                try:
                    self_ip = socket.gethostbyname(socket.gethostname())
                except socket.error:
                    print(">> Could not get your IP address from your " \
                          "DNS Server.")
                    self_ip = '127.0.0.1'
                ips[ips.index(ip)] = self_ip
        return ips


    def __init__(self, file_):
        """
        Parses the DNS Rulefile, validates the rules, replaces keywords
        """

        # track DNS requests here
        self.match_history = {}

        self.rule_list = []

        # A lol.com IP1,IP2,IP3,IP4,IP5,IP6 rebind_threshold%Rebind_IP1,Rebind_IP2
        with open(file_, 'r') as rulefile:
            rules = rulefile.readlines()
            lineno = 0 # keep track of line number for errors

            for rule in rules:

                # ignore blank lines or lines starting with hashmark (coments)
                if len(rule.strip()) == 0 or rule.lstrip()[0] == "#" or rule == '\n':
                    # thank you to github user cambid for the comments suggestion
                    continue

                # Confirm that the rule has at least three columns to it
                if len(rule.split()) < 3:
                    raise RuleError_BadFormat(lineno)

                # break the rule out into its components
                s_rule = rule.split()
                rule_type = s_rule[0].upper()
                domain = s_rule[1]
                ips = s_rule[2].split(',') # allow multiple ip's thru commas

                # only try this if the rule is long enough
                if len(s_rule) == 4:
                    rebinds = s_rule[3]
                    # handle old rule style (maybe someone updated)
                    if '%' in rebinds:
                        rebind_threshold,rebinds = rebinds.split('%')
                        rebinds = rebinds.split(',')
                        rebind_threshold = int(rebind_threshold)
                    else:
                        # in the old days we assumed a rebind thresh of 1
                        rebind_threshold = 1
                else:
                    rebinds = None
                    rebind_threshold = None

                # Validate the rule
                # make sure we understand this type of response
                if rule_type not in TYPE.values():
                    raise RuleError_BadRuleType(lineno)
                # attempt to parse the regex (if any) in the domain field
                try:
                    domain = re.compile(domain, flags=re.IGNORECASE)
                except:
                    raise RuleError_BadRegularExpression(lineno)

                # replace self in the list of ips and list of rebinds (if any)
                ips = self._replace_self(ips)
                if rebinds is not None:
                    rebinds = self._replace_self(rebinds)

                # Deal With Special IPv6 Nonsense
                if rule_type.upper() == "AAAA":
                    tmp_ip_array = []
                    for ip in ips:
                        if ip.lower() == 'none':
                            tmp_ip_array.append(ip)
                            continue
                        if _is_shorthand_ip(ip):
                            ip = _explode_shorthand_ip_string(ip)
                        ip = binascii.unhexlify(ip.replace(":", "")) #.decode('hex')
                        tmp_ip_array.append(ip)
                    ips = tmp_ip_array


                # add the validated and parsed rule into our list of rules
                self.rule_list.append(Rule(rule_type, domain, ips, rebinds, rebind_threshold))

                # increment the line number
                lineno += 1

            print(">> Parsed %d rules from %s" % (len(self.rule_list),file_))


    def match(self, query, addr):
        """
        See if the request matches any rules in the rule list by calling the
        match function of each rule in the list
        The rule checks two things before it continues so I imagine this is
        probably still fast
        """
        for rule in self.rule_list:
            result = rule.match(query.type, query.domain, addr)
            if result is not None:
                response_data = result

                # Return Nonefound if the rule says "none"
                if response_data.lower() == 'none':
                    return NONEFOUND(query).make_packet()

                response = CASE[query.type](query, response_data)

                print(">> Matched Request - " + query.domain.decode())
                return response.make_packet()

        # if we got here, we didn't match.
        # Forward a request that we didnt have a rule for to someone else

        # if the user said not to forward requests, and we are here, it's time to send a NONEFOUND
        if args.noforward:
            print(">> Don't Forward %s" % query.domain.decode())
            return NONEFOUND(query).make_packet()
        try:
            s = socket.socket(type=socket.SOCK_DGRAM)
            s.settimeout(3.0)
            addr = ('%s' % (args.dns), 53)
            s.sendto(query.data, addr)
            data = s.recv(1024)
            s.close()
            print("Unmatched Request " + query.domain.decode())
            return data
        except socket.error as e:
            # We shouldn't wind up here but if we do, don't drop the request
            # send the client *something*
            print(">> Error was handled by sending NONEFOUND")
            print(e)
            return NONEFOUND(query).make_packet()


# Convenience method for threading.
def respond(data, addr, s):
    p = DNSQuery(data)
    response = rules.match(p, addr[0])
    s.sendto(response, addr)
    return response

# Capture Control-C and handle here
def signal_handler(signal, frame):
    print('Exiting...')
    sys.exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='FakeDNS - A Python DNS Server')
    parser.add_argument(
        '-c', dest='path', action='store', required=True,
        help='Path to configuration file')
    parser.add_argument(
        '-i', dest='iface', action='store', default='0.0.0.0', required=False,
        help='IP address you wish to run FakeDns with - default all')
    parser.add_argument(
        '-p', dest='port', action='store', default=53, required=False,
        help='Port number you wish to run FakeDns')
    parser.add_argument(
        '--rebind', dest='rebind', action='store_true', required=False,
        default=False, help="Enable DNS rebinding attacks - responds with one "
        "result the first request, and another result on subsequent requests")
    parser.add_argument(
        '--dns', dest='dns', action='store', default='8.8.8.8', required=False,
        help='IP address of the upstream dns server - default 8.8.8.8'
    )
    parser.add_argument(
        '--noforward', dest='noforward', action='store_true', default=False, required=False,
        help='Sets if FakeDNS should forward any non-matching requests'
    )

    # todo: remove this - it's confusing, and we should be able to set this per-record. Keep for now for quickness.
    parser.add_argument(
        '--non-authoritative', dest='non_authoritative', action='store_true', default=False, required=False,
        help='Sets if FakeDNS should not report as an authority for any matching DNS Queries'
    )

    args = parser.parse_args()

    # if non-authoritative is set to true, it'll cancel out the default authoritative setting
    # this is a not-very-coherent way to pull this off but we'll be changing the behavior of FakeDNS soon so it's OK
    args.authoritative = True ^ args.non_authoritative

    # Default config file path.
    path = args.path
    if not os.path.isfile(path):
        print('>> Please create a "dns.conf" file or specify a config path: ' \
              './fakedns.py [configfile]')
        exit()

    rules = RuleEngine2(path)
    rule_list = rules.rule_list

    interface = args.iface
    port = args.port

    try:
        server = ThreadedUDPServer((interface, int(port)), UDPHandler)
    except socket.error:
        print(">> Could not start server -- is another program on udp:{0}?".format(port))
        exit(1)

    server.daemon = True

    # Tell python what happens if someone presses ctrl-C
    signal.signal(signal.SIGINT, signal_handler)
    server.serve_forever()
    server_thread.join()
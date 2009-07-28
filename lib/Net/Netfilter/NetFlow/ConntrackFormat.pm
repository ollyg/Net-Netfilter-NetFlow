package Net::Netfilter::NetFlow::ConntrackFormat;

use strict;
use warnings FATAL => 'all';

use base 'Exporter';
our @EXPORT = qw(
    ct_new_key
    ct_destroy_key
    ct_mask_fields
);

# 1:icmp - src,src,dst,id
# 6:tcp  - src,sport,src,sport,dst,dport
# 17:udp - src,sport,src,sport,dst,dport
# first src is private, second is public (post SNAT)

my %ct_new_key = (
    1  => [4,11,5,8],
    6  => [5,7,11,13,6,8],
    17 => [4,6,10,12,5,7],
);

my %ct_destroy_key = (
    1  => [3,11,4,7],
    6  => [3,5,10,12,4,6],
    17 => [3,5,10,12,4,6],
);

# dpkts, doctets, srcaddr, dstaddr, srcport, dstport
my %ct_mask_fields = (
    1 => {
        # field 17 does not exist
        private_src => [8,9,3,4,17,17],
        public_src  => [8,9,11,10,17,17],
        dst => [15,16,10,11,17,17],
    },
    6 => {
        private_src => [7,8,3,4,5,6],
        public_src  => [7,8,10,9,12,11],
        dst => [13,14,9,10,11,12],
    },
    17 => {
        private_src => [7,8,3,4,5,6],
        public_src  => [7,8,10,9,12,11],
        dst => [13,14,9,10,11,12],
    },
);

__END__
input examples:

1229102644.806690       NEW      1 30 10.16.207.250 18.7.22.83 8 0 1035 UNREPLIED 18.7.22.83 192.76.7.254 0 0 0
1229102644.906091   DESTROY      1 10.16.207.250 18.7.22.83 8 0 1035 1 84 18.7.22.83 192.76.7.254 0 0 0 0 0

[1229102644.806690]>    [NEW] icmp     1 30 src=10.16.207.250 dst=18.7.22.83 type=8 code=0 id=1035 [UNREPLIED] src=18.7.22.83 dst=192.76.7.254 type=0 code=0 id=0
[1229102644.906091]>[DESTROY] icmp     1 src=10.16.207.250 dst=18.7.22.83 type=8 code=0 id=1035 packets=1 bytes=84 src=18.7.22.83 dst=192.76.7.254 type=0 code=0 id=0 packets=0 bytes=0
[1229102649.886279]>    [NEW] tcp      6 120 SYN_SENT src=10.16.207.250 dst=74.125.79.104 sport=50140 dport=80 [UNREPLIED] src=74.125.79.104 dst=192.76.7.253 sport=80 dport=61284
[1229102719.964446]>[DESTROY] tcp      6 src=10.16.207.250 dst=74.125.79.104 sport=50140 dport=80 packets=7 bytes=2006 src=74.125.79.104 dst=192.76.7.253 sport=80 dport=61284 packets=7 bytes=4083
[1229102658.898013]>    [NEW] udp      17 30 src=10.16.207.250 dst=192.76.27.246 sport=4500 dport=4500 [UNREPLIED] src=192.76.27.246 dst=192.76.7.254 sport=4500 dport=9234
[1229102851.680437]>[DESTROY] udp      17 src=10.16.207.250 dst=192.76.27.246 sport=4500 dport=4500 packets=655 bytes=190269 src=192.76.27.246 dst=192.76.7.254 sport=4500 dport=9234 packets=916 bytes=609824

output example:
mask 0xFF31EF

UNIX_SECS       0x0000000000000001LL Current count of seconds since 0000 UTC 1970
UNIX_NSECS      0x0000000000000002LL Residual nanoseconds since 0000 UTC 1970
SYSUPTIME       0x0000000000000004LL Current time in milliseconds since the export device booted
EXADDR          0x0000000000000008LL Export device IP address
DPKTS           0x0000000000000020LL Packets in the flow
DOCTETS         0x0000000000000040LL Total number of Layer 3 bytes in the packets of the flow
FIRST           0x0000000000000080LL SysUptime at start of flow
LAST            0x0000000000000100LL SysUptime at the time the last packet of the flow was received
SRCADDR         0x0000000000001000LL Source IP address
DSTADDR         0x0000000000002000LL Destination IP address
NEXTHOP         0x0000000000010000LL IP address of next hop router
INPUT           0x0000000000020000LL SNMP index of input interface
OUTPUT          0x0000000000040000LL SNMP index of output interface
SRCPORT         0x0000000000080000LL TCP/UDP source port number or equivalent
DSTPORT         0x0000000000100000LL TCP/UDP source port number or equivalent
PROT            0x0000000000200000LL IP protocol type (for example, TCP = 6; UDP = 17)
TOS             0x0000000000400000LL IP type of service (ToS)
TCP_FLAGS       0x0000000000800000LL Cumulative OR of TCP flags


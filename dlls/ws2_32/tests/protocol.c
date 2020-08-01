/*
 * Unit test suite for protocol functions
 *
 * Copyright 2004 Hans Leidekker
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include <windef.h>
#include <winbase.h>
#include <winsock2.h>

#include "wine/test.h"

/* TCP and UDP over IP fixed set of service flags */
#define TCPIP_SERVICE_FLAGS (XP1_GUARANTEED_DELIVERY \
                           | XP1_GUARANTEED_ORDER    \
                           | XP1_GRACEFUL_CLOSE      \
                           | XP1_EXPEDITED_DATA      \
                           | XP1_IFS_HANDLES)

#define UDPIP_SERVICE_FLAGS (XP1_CONNECTIONLESS      \
                           | XP1_MESSAGE_ORIENTED    \
                           | XP1_SUPPORT_BROADCAST   \
                           | XP1_SUPPORT_MULTIPOINT  \
                           | XP1_IFS_HANDLES)

#define PRIVATE_PORT_START 49152

#define TEST_TIMEOUT 30    /* Seconds to wait before killing child threads
                              after server initialization, if something hangs */
#define NUM_THREADS 3      /* Number of threads to run getservbyname */
#define NUM_QUERIES 250    /* Number of getservbyname queries per thread */

static void test_service_flags(int family, int version, int socktype, int protocol, DWORD testflags)
{
    DWORD expectedflags = 0;
    if (socktype == SOCK_STREAM && protocol == IPPROTO_TCP)
        expectedflags = TCPIP_SERVICE_FLAGS;
    if (socktype == SOCK_DGRAM && protocol == IPPROTO_UDP)
        expectedflags = UDPIP_SERVICE_FLAGS;

    /* check if standard TCP and UDP protocols are offering the correct service flags */
    if ((family == AF_INET || family == AF_INET6) && version == 2 && expectedflags)
    {
        /* QOS may or may not be installed */
        testflags &= ~XP1_QOS_SUPPORTED;
        ok(expectedflags == testflags,
           "Incorrect flags, expected 0x%x, received 0x%x\n",
           expectedflags, testflags);
    }
}

static void test_WSAEnumProtocolsA(void)
{
    INT ret, i, j, found;
    DWORD len = 0, error;
    WSAPROTOCOL_INFOA info, *buffer;
    INT ptest[] = {0xdead, IPPROTO_TCP, 0xcafe, IPPROTO_UDP, 0xbeef, 0};

    ret = WSAEnumProtocolsA( NULL, NULL, &len );
    ok( ret == SOCKET_ERROR, "WSAEnumProtocolsA() succeeded unexpectedly\n");
    error = WSAGetLastError();
    ok( error == WSAENOBUFS, "Expected 10055, received %d\n", error);

    len = 0;

    ret = WSAEnumProtocolsA( NULL, &info, &len );
    ok( ret == SOCKET_ERROR, "WSAEnumProtocolsA() succeeded unexpectedly\n");
    error = WSAGetLastError();
    ok( error == WSAENOBUFS, "Expected 10055, received %d\n", error);

    buffer = HeapAlloc( GetProcessHeap(), 0, len );

    if (buffer)
    {
        ret = WSAEnumProtocolsA( NULL, buffer, &len );
        ok( ret != SOCKET_ERROR, "WSAEnumProtocolsA() failed unexpectedly: %d\n",
            WSAGetLastError() );

        for (i = 0; i < ret; i++)
        {
            ok( strlen( buffer[i].szProtocol ), "No protocol name found\n" );
            test_service_flags( buffer[i].iAddressFamily, buffer[i].iVersion,
                                buffer[i].iSocketType, buffer[i].iProtocol,
                                buffer[i].dwServiceFlags1);
        }

        HeapFree( GetProcessHeap(), 0, buffer );
    }

    /* Test invalid protocols in the list */
    ret = WSAEnumProtocolsA( ptest, NULL, &len );
    ok( ret == SOCKET_ERROR, "WSAEnumProtocolsA() succeeded unexpectedly\n");
    error = WSAGetLastError();
    ok( error == WSAENOBUFS || broken(error == WSAEFAULT) /* NT4 */,
       "Expected 10055, received %d\n", error);

    buffer = HeapAlloc( GetProcessHeap(), 0, len );

    if (buffer)
    {
        ret = WSAEnumProtocolsA( ptest, buffer, &len );
        ok( ret != SOCKET_ERROR, "WSAEnumProtocolsA() failed unexpectedly: %d\n",
            WSAGetLastError() );
        ok( ret >= 2, "Expected at least 2 items, received %d\n", ret);

        for (i = found = 0; i < ret; i++)
            for (j = 0; j < ARRAY_SIZE(ptest); j++)
                if (buffer[i].iProtocol == ptest[j])
                {
                    found |= 1 << j;
                    break;
                }
        ok(found == 0x0A, "Expected 2 bits represented as 0xA, received 0x%x\n", found);

        HeapFree( GetProcessHeap(), 0, buffer );
    }
}

static void test_WSAEnumProtocolsW(void)
{
    INT ret, i, j, found;
    DWORD len = 0, error;
    WSAPROTOCOL_INFOW info, *buffer;
    INT ptest[] = {0xdead, IPPROTO_TCP, 0xcafe, IPPROTO_UDP, 0xbeef, 0};

    ret = WSAEnumProtocolsW( NULL, NULL, &len );
    ok( ret == SOCKET_ERROR, "WSAEnumProtocolsW() succeeded unexpectedly\n");
    error = WSAGetLastError();
    ok( error == WSAENOBUFS, "Expected 10055, received %d\n", error);

    len = 0;

    ret = WSAEnumProtocolsW( NULL, &info, &len );
    ok( ret == SOCKET_ERROR, "WSAEnumProtocolsW() succeeded unexpectedly\n");
    error = WSAGetLastError();
    ok( error == WSAENOBUFS, "Expected 10055, received %d\n", error);

    buffer = HeapAlloc( GetProcessHeap(), 0, len );

    if (buffer)
    {
        ret = WSAEnumProtocolsW( NULL, buffer, &len );
        ok( ret != SOCKET_ERROR, "WSAEnumProtocolsW() failed unexpectedly: %d\n",
            WSAGetLastError() );

        for (i = 0; i < ret; i++)
        {
            ok( lstrlenW( buffer[i].szProtocol ), "No protocol name found\n" );
            test_service_flags( buffer[i].iAddressFamily, buffer[i].iVersion,
                                buffer[i].iSocketType, buffer[i].iProtocol,
                                buffer[i].dwServiceFlags1);
        }

        HeapFree( GetProcessHeap(), 0, buffer );
    }

    /* Test invalid protocols in the list */
    ret = WSAEnumProtocolsW( ptest, NULL, &len );
    ok( ret == SOCKET_ERROR, "WSAEnumProtocolsW() succeeded unexpectedly\n");
    error = WSAGetLastError();
    ok( error == WSAENOBUFS || broken(error == WSAEFAULT) /* NT4 */,
       "Expected 10055, received %d\n", error);

    buffer = HeapAlloc( GetProcessHeap(), 0, len );

    if (buffer)
    {
        ret = WSAEnumProtocolsW( ptest, buffer, &len );
        ok( ret != SOCKET_ERROR, "WSAEnumProtocolsW() failed unexpectedly: %d\n",
            WSAGetLastError() );
        ok( ret >= 2, "Expected at least 2 items, received %d\n", ret);

        for (i = found = 0; i < ret; i++)
            for (j = 0; j < ARRAY_SIZE(ptest); j++)
                if (buffer[i].iProtocol == ptest[j])
                {
                    found |= 1 << j;
                    break;
                }
        ok(found == 0x0A, "Expected 2 bits represented as 0xA, received 0x%x\n", found);

        HeapFree( GetProcessHeap(), 0, buffer );
    }
}

struct protocol
{
    int prot;
    const char *names[2];
    BOOL missing_from_xp;
};

static const struct protocol protocols[] =
{
    {   0, { "ip", "IP" }},
    {   1, { "icmp", "ICMP" }},
    {   3, { "ggp", "GGP" }},
    {   6, { "tcp", "TCP" }},
    {   8, { "egp", "EGP" }},
    {  12, { "pup", "PUP" }},
    {  17, { "udp", "UDP" }},
    {  20, { "hmp", "HMP" }},
    {  22, { "xns-idp", "XNS-IDP" }},
    {  27, { "rdp", "RDP" }},
    {  41, { "ipv6", "IPv6" }, TRUE},
    {  43, { "ipv6-route", "IPv6-Route" }, TRUE},
    {  44, { "ipv6-frag", "IPv6-Frag" }, TRUE},
    {  50, { "esp", "ESP" }, TRUE},
    {  51, { "ah", "AH" }, TRUE},
    {  58, { "ipv6-icmp", "IPv6-ICMP" }, TRUE},
    {  59, { "ipv6-nonxt", "IPv6-NoNxt" }, TRUE},
    {  60, { "ipv6-opts", "IPv6-Opts" }, TRUE},
    {  66, { "rvd", "RVD" }},
};

static const struct protocol *find_protocol(int number)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(protocols); i++)
    {
        if (protocols[i].prot == number)
            return &protocols[i];
    }
    return NULL;
}

static void test_getprotobyname(void)
{
    struct protoent *ent;
    char all_caps_name[16];
    int i, j;

    for (i = 0; i < ARRAY_SIZE(protocols); i++)
    {
        for (j = 0; j < ARRAY_SIZE(protocols[0].names); j++)
        {
            ent = getprotobyname(protocols[i].names[j]);
            ok((ent && ent->p_proto == protocols[i].prot) || broken(!ent && protocols[i].missing_from_xp),
               "Expected %s to be protocol number %d, got %d\n",
               wine_dbgstr_a(protocols[i].names[j]), protocols[i].prot, ent ? ent->p_proto : -1);
        }

        for (j = 0; protocols[i].names[0][j]; j++)
            all_caps_name[j] = toupper(protocols[i].names[0][j]);
        all_caps_name[j] = 0;
        ent = getprotobyname(all_caps_name);
        ok((ent && ent->p_proto == protocols[i].prot) || broken(!ent && protocols[i].missing_from_xp),
           "Expected %s to be protocol number %d, got %d\n",
           wine_dbgstr_a(all_caps_name), protocols[i].prot, ent ? ent->p_proto : -1);
    }
}

static void test_getprotobynumber(void)
{
    struct protoent *ent;
    const struct protocol *ref;
    int i;

    for (i = -1; i <= 256; i++)
    {
        ent = getprotobynumber(i);
        ref = find_protocol(i);

        if (!ref)
        {
            ok(!ent, "Expected protocol number %d to be undefined, got %s\n",
               i, wine_dbgstr_a(ent ? ent->p_name : NULL));
            continue;
        }

        ok((ent && ent->p_name && strcmp(ent->p_name, ref->names[0]) == 0) ||
           broken(!ent && ref->missing_from_xp),
           "Expected protocol number %d to be %s, got %s\n",
           i, ref->names[0], wine_dbgstr_a(ent ? ent->p_name : NULL));

        ok((ent && ent->p_aliases && ent->p_aliases[0] &&
            strcmp(ent->p_aliases[0], ref->names[1]) == 0) ||
           broken(!ent && ref->missing_from_xp),
           "Expected protocol number %d alias 0 to be %s, got %s\n",
           i, ref->names[0], wine_dbgstr_a(ent && ent->p_aliases ? ent->p_aliases[0] : NULL));
    }
}

struct service
{
    unsigned short port;
    const char *names[2];
    const char *protos[2];
    enum { MISSING = 0x1, RENAMED = 0x2 } flags;
};

static const struct service services[] =
{
    {     7, {"echo"}, {"tcp", "udp"} },
    {     9, {"discard", "sink"}, {"tcp", "udp"} },
    {    11, {"systat", "users"}, {"tcp", "udp"}, MISSING /* xp */ },
    {    13, {"daytime"}, {"tcp", "udp"} },
    {    17, {"qotd", "quote"}, {"tcp", "udp"} },
    {    19, {"chargen", "ttytst"}, {"tcp", "udp"} },
    {    20, {"ftp-data"}, {"tcp"} },
    {    21, {"ftp"}, {"tcp"} },
    {    22, {"ssh"}, {"tcp"}, MISSING /* xp */ },
    {    23, {"telnet"}, {"tcp"} },
    {    25, {"smtp", "mail"}, {"tcp"} },
    {    37, {"time", "timserver"}, {"tcp", "udp"} },
    {    39, {"rlp", "resource"}, {"udp"} },
    {    42, {"nameserver", "name"}, {"tcp", "udp"} },
    {    43, {"nicname", "whois"}, {"tcp"} },
    {    53, {"domain"}, {"tcp", "udp"} },
    {    67, {"bootps", "dhcps"}, {"udp"} },
    {    68, {"bootpc", "dhcpc"}, {"udp"} },
    {    69, {"tftp"}, {"udp"} },
    {    70, {"gopher"}, {"tcp"} },
    {    79, {"finger"}, {"tcp"} },
    {    80, {"http", "www"}, {"tcp"} },
    {    81, {"hosts2-ns"}, {"tcp", "udp"}, MISSING /* xp */ },
    {    88, {"kerberos", "krb5"}, {"tcp", "udp"} },
    {   101, {"hostname", "hostnames"}, {"tcp"} },
    {   102, {"iso-tsap"}, {"tcp"} },
    {   107, {"rtelnet"}, {"tcp"} },
    {   109, {"pop2", "postoffice"}, {"tcp"} },
    {   110, {"pop3"}, {"tcp"} },
    {   111, {"sunrpc", "rpcbind"}, {"tcp", "udp"} },
    {   113, {"auth", "ident"}, {"tcp"} },
    {   117, {"uucp-path"}, {"tcp"} },
    {   118, {"sqlserv"}, {"tcp"}, MISSING /* xp */ },
    {   119, {"nntp", "usenet"}, {"tcp"} },
    {   123, {"ntp"}, {"udp"} },
    {   135, {"epmap", "loc-srv"}, {"tcp", "udp"} },
    {   137, {"netbios-ns", "nbname"}, {"tcp", "udp"} },
    {   138, {"netbios-dgm", "nbdatagram"}, {"udp"} },
    {   139, {"netbios-ssn", "nbsession"}, {"tcp"} },
    {   143, {"imap", "imap4"}, {"tcp"} },
    {   150, {"sql-net"}, {"tcp"}, MISSING /* xp */ },
    {   156, {"sqlsrv"}, {"tcp"}, MISSING /* xp */ },
    {   158, {"pcmail-srv"}, {"tcp"} },
    {   161, {"snmp"}, {"udp"} },
    {   162, {"snmptrap", "snmp-trap"}, {"udp"} },
    {   170, {"print-srv"}, {"tcp"} },
    {   179, {"bgp"}, {"tcp"} },
    {   194, {"irc"}, {"tcp"} },
    {   213, {"ipx"}, {"udp"} },
    {   322, {"rtsps"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   349, {"mftp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   389, {"ldap"}, {"tcp"} },
    {   443, {"https", "MCom"}, {"tcp", "udp"} },
    {   445, {"microsoft-ds"}, {"tcp", "udp"} },
    {   464, {"kpasswd"}, {"tcp", "udp"} },
    {   500, {"isakmp", "ike"}, {"udp"} },
    {   507, {"crs"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   512, {"exec"}, {"tcp"} },
    {   512, {"biff", "comsat"}, {"udp", "tcp"}, MISSING /* win10 */ },
    {   513, {"login"}, {"tcp"} },
    {   513, {"who", "whod"}, {"udp", "tcp"}, MISSING /* win10 */ },
    {   514, {"cmd", "shell"}, {"tcp"} },
    {   514, {"syslog"}, {"udp", "tcp"}, MISSING /* win10 */ },
    {   515, {"printer", "spooler"}, {"tcp"} },
    {   517, {"talk"}, {"udp"} },
    {   518, {"ntalk"}, {"udp"} },
    {   520, {"efs"}, {"tcp"} },
    {   520, {"router", "route"}, {"udp", "tcp"}, MISSING /* win10 */ },
    {   522, {"ulp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   525, {"timed", "timeserver"}, {"udp"} },
    {   526, {"tempo", "newdate"}, {"tcp"} },
    {   529, {"irc-serv"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   530, {"courier", "rpc"}, {"tcp"} },
    {   531, {"conference", "chat"}, {"tcp"} },
    {   532, {"netnews", "readnews"}, {"tcp"} },
    {   533, {"netwall"}, {"udp"} },
    {   540, {"uucp", "uucpd"}, {"tcp"} },
    {   543, {"klogin"}, {"tcp"} },
    {   544, {"kshell", "krcmd"}, {"tcp"} },
    {   546, {"dhcpv6-client"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   547, {"dhcpv6-server"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   548, {"afpovertcp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   550, {"new-rwho", "new-who"}, {"udp"} },
    {   554, {"rtsp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   556, {"remotefs", "rfs"}, {"tcp"} },
    {   560, {"rmonitor", "rmonitord"}, {"udp"} },
    {   561, {"monitor"}, {"udp"} },
    {   563, {"nntps", "snntp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   565, {"whoami"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   568, {"ms-shuttle"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   569, {"ms-rome"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   593, {"http-rpc-epmap"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   612, {"hmmp-ind"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   613, {"hmmp-op"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   636, {"ldaps", "sldap"}, {"tcp"} },
    {   666, {"doom"}, {"tcp", "udp"} },
    {   691, {"msexch-routing"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   749, {"kerberos-adm"}, {"tcp", "udp"} },
    {   750, {"kerberos-iv"}, {"udp"} },
    {   800, {"mdbs_daemon"}, {"tcp", "udp"}, MISSING /* xp */ },
    {   989, {"ftps-data"}, {"tcp"}, MISSING /* xp */ },
    {   990, {"ftps"}, {"tcp"}, MISSING /* xp */ },
    {   992, {"telnets"}, {"tcp"}, MISSING /* xp */ },
    {   993, {"imaps"}, {"tcp"}, MISSING /* xp */ },
    {   994, {"ircs"}, {"tcp"}, MISSING /* xp */ },
    {   995, {"pop3s", "spop3"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1034, {"activesync"}, {"tcp"}, MISSING /* xp */ },
    {  1109, {"kpop"}, {"tcp"} },
    {  1110, {"nfsd-status"}, {"tcp"}, MISSING /* xp */ },
    {  1110, {"nfsd-keepalive"}, {"udp"}, MISSING /* xp */ },
    {  1155, {"nfa"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1167, {"phone"}, {"udp"} },
    {  1270, {"opsmgr"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1433, {"ms-sql-s"}, {"tcp", "udp"} },
    {  1434, {"ms-sql-m"}, {"tcp", "udp"} },
    {  1477, {"ms-sna-server"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1478, {"ms-sna-base"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1512, {"wins"}, {"tcp", "udp"} },
    {  1524, {"ingreslock", "ingres"}, {"tcp"} },
    {  1607, {"stt"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1701, {"l2tp"}, {"udp"} },
    {  1711, {"pptconference"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1723, {"pptp"}, {"tcp"} },
    {  1731, {"msiccp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1745, {"remote-winsock"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1755, {"ms-streaming"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1801, {"msmq"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1812, {"radius"}, {"udp"} },
    {  1813, {"radacct"}, {"udp"} },
    {  1863, {"msnp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1900, {"ssdp"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  1944, {"close-combat"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2049, {"nfsd", "nfs"}, {"udp"} },
    {  2053, {"knetd"}, {"tcp"} },
    {  2106, {"mzap"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2177, {"qwave"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2234, {"directplay"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2382, {"ms-olap3"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2383, {"ms-olap4"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2393, {"ms-olap1"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2394, {"ms-olap2"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2460, {"ms-theater"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2504, {"wlbs"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2525, {"ms-v-worlds"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2701, {"sms-rcinfo"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2702, {"sms-xfer"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2703, {"sms-chat"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2704, {"sms-remctrl"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2725, {"msolap-ptp2"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  2869, {"icslap"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3020, {"cifs"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3074, {"xbox"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3126, {"ms-dotnetster"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3132, {"ms-rule-engine"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3268, {"msft-gc"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3269, {"msft-gc-ssl"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3343, {"ms-cluster-net"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3389, {"ms-wbt-server"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3535, {"ms-la"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3540, {"pnrp-port"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3544, {"teredo"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3587, {"p2pgroup"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3702, {"ws-discovery", "upnp-discovery"}, {"udp", "tcp"}, MISSING /* xp */ | RENAMED /* 2008 */ },
    {  3776, {"dvcprov-port"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  3847, {"msfw-control"}, {"tcp"}, MISSING /* xp */ },
    {  3882, {"msdts1"}, {"tcp"}, MISSING /* xp */ },
    {  3935, {"sdp-portmapper"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  4350, {"net-device"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  4500, {"ipsec-msft"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  5355, {"llmnr"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  5357, {"wsd"}, {"tcp"}, MISSING /* xp */ },
    {  5358, {"wsd"}, {"tcp"}, MISSING /* xp */ },
    {  5678, {"rrac"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  5679, {"dccm"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  5720, {"ms-licensing"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  6073, {"directplay8"}, {"tcp", "udp"}, MISSING /* xp */ },
    {  9535, {"man"}, {"tcp"} },
    {  9753, {"rasadv"}, {"tcp", "udp"}, MISSING /* xp */ },
    { 11320, {"imip-channels"}, {"tcp", "udp"}, MISSING /* xp */ },
    { 47624, {"directplaysrvr"}, {"tcp", "udp"}, MISSING /* xp */ },
};

static const struct service *find_service(int port, const char *proto)
{
    int i, j;
    for (i = 0; i < ARRAY_SIZE(services) && services[i].port <= port; i++)
    {
        if (services[i].port != port) continue;
        for (j = 0; j < ARRAY_SIZE(services[0].protos) && services[i].protos[j]; j++)
        {
            if (!proto || _stricmp(proto, services[i].protos[j]) == 0)
                return &services[i];
        }
    }
    return NULL;
}

static DWORD WINAPI do_getservbyname(void *param)
{
    HANDLE *starttest = param;
    int i, j, k, l;
    struct servent *results[ARRAY_SIZE(services)];
    char all_caps_name[16];

    if (starttest)
    {
        ok(WaitForSingleObject(*starttest, TEST_TIMEOUT * 1000) != WAIT_TIMEOUT,
           "test_getservbyname: timeout waiting for start signal\n");
    }

    /* ensure that necessary buffer resizes are completed */
    for (i = 0; i < 2; i++)
        results[i] = getservbyname(services[i].names[0], NULL);

    for (i = 0; i < (starttest ? NUM_QUERIES / 2 : 1); i++)
    {
        for (j = 0; j < (starttest ? 2 : ARRAY_SIZE(services)); j++)
        {
            if (j > 0 && strcmp(services[j].names[0], services[j-1].names[0]) == 0) continue;
            for (k = 0; k < ARRAY_SIZE(services[0].names) && services[j].names[k]; k++)
            {
                for (l = 0; services[j].names[k][l]; l++)
                    all_caps_name[l] = toupper(services[j].names[k][l]);
                all_caps_name[l] = 0;
                for (l = 0; l < ARRAY_SIZE(services[0].protos); l++)
                {
                    results[j] = getservbyname(services[j].names[k], services[j].protos[l]);
                    ok(results[j] != NULL || broken(services[j].flags & MISSING),
                       "getservbyname could not retrieve information for %s/%s: %d\n",
                       services[j].names[k], wine_dbgstr_a(services[j].protos[l]), WSAGetLastError());
                    if (!results[j]) continue;
                    ok(ntohs(results[j]->s_port) == services[j].port,
                       "getservbyname returned the wrong port for %s/%s: %d\n",
                       services[j].names[k], wine_dbgstr_a(services[j].protos[l]), ntohs(results[j]->s_port));
                    ok(!strcmp(results[j]->s_proto, services[j].protos[l] ? services[j].protos[l] : services[j].protos[0]),
                       "getservbyname returned the wrong protocol for %s/%s: %s\n",
                       services[j].names[k], wine_dbgstr_a(services[j].protos[l]), results[j]->s_proto);
                    ok(!strcmp(results[j]->s_name, services[j].names[0]) ||
                       broken((services[j].flags & RENAMED) && !strcmp(results[j]->s_name, services[j].names[1])),
                       "getservbyname returned the wrong name for %s/%s: %s\n",
                       services[j].names[k], wine_dbgstr_a(services[j].protos[l]), results[j]->s_name);

                    results[j] = getservbyname(all_caps_name, services[j].protos[l]);
                    ok(ntohs(results[j]->s_port) == services[j].port,
                       "getservbyname returned the wrong port for %s/%s: %d\n",
                       all_caps_name, wine_dbgstr_a(services[j].protos[l]), ntohs(results[j]->s_port));
                    ok(!strcmp(results[j]->s_proto, services[j].protos[l] ? services[j].protos[l] : services[j].protos[0]),
                       "getservbyname returned the wrong protocol for %s/%s: %s\n",
                       all_caps_name, wine_dbgstr_a(services[j].protos[l]), results[j]->s_proto);
                    ok(!strcmp(results[j]->s_name, services[j].names[0]) ||
                       broken((services[j].flags & RENAMED) && !strcmp(results[j]->s_name, services[j].names[1])),
                       "getservbyname returned the wrong name for %s/%s: %s\n",
                       all_caps_name, wine_dbgstr_a(services[j].protos[l]), results[j]->s_name);
                }
            }
        }
        ok(results[0] == results[1],
           "getservbyname: winsock resized servent buffer when not necessary\n");
    }

    return 0;
}

static void test_getservbyname(void)
{
    int i;
    HANDLE starttest, thread[NUM_THREADS];
    DWORD thread_id[NUM_THREADS];

    /* test the complete list of service entries */
    do_getservbyname(NULL);

    /* test thread safety using just the first two service entries */
    starttest = CreateEventA(NULL, 1, 0, "test_getservbyname_starttest");

    /* create threads */
    for (i = 0; i < NUM_THREADS; i++)
        thread[i] = CreateThread(NULL, 0, do_getservbyname, &starttest, 0, &thread_id[i]);

    /* signal threads to start */
    SetEvent(starttest);

    for (i = 0; i < NUM_THREADS; i++)
        WaitForSingleObject(thread[i], TEST_TIMEOUT * 1000);
}

static void test_getservbyport(void)
{
    static const char *test_protos[] = { NULL, "tcp", "udp", "icmp", "Tcp", "udP" };
    struct servent *ent;
    const struct service *ref;
    int i, j;

    /* Testing all port/protocol combinations takes a very long time on Windows. To avoid timeouts,
     * don't test the private port range and skip the tests for specific protocols if there is no
     * defined service on a particular port for any protocol. */
    for (i = 0; i <= PRIVATE_PORT_START; i++)
    {
        for (j = 0; j < ARRAY_SIZE(test_protos); j++)
        {
            ent = getservbyport(htons(i), test_protos[j]);
            ref = find_service(i, test_protos[j]);

            if (!ref)
            {
                ok(!ent, "Expected service %d/%s to be undefined, got %s\n",
                   i, wine_dbgstr_a(test_protos[j]), wine_dbgstr_a(ent ? ent->s_name : NULL));
                if (!ent && j == 0) break;
                continue;
            }

            ok((ent && ent->s_name && strcmp(ent->s_name, ref->names[0]) == 0) ||
               broken((ref->flags & MISSING) && !ent) ||
               broken((ref->flags & RENAMED) && ent && ent->s_name && strcmp(ent->s_name, ref->names[1]) == 0),
               "Expected service %d/%s to be %s, got %s\n",
               i, wine_dbgstr_a(test_protos[j]), wine_dbgstr_a(ref->names[0]),
               wine_dbgstr_a(ent ? ent->s_name : NULL));

            if (ref->names[1])
            {
                ok((ent && ent->s_aliases && ent->s_aliases[0] &&
                    strcmp(ent->s_aliases[0], ref->names[1]) == 0) ||
                   broken((ref->flags & MISSING) && !ent) ||
                   broken((ref->flags & RENAMED) && ent && ent->s_aliases && !ent->s_aliases[0]),
                   "Expected service %d/%s alias 0 to be %s, got %s\n",
                   i, wine_dbgstr_a(test_protos[j]), wine_dbgstr_a(ref->names[1]),
                   wine_dbgstr_a(ent && ent->s_aliases ? ent->s_aliases[0] : NULL));
            }
            else
            {
                ok((ent && ent->s_aliases && !ent->s_aliases[0]) ||
                   broken((ref->flags & MISSING) && !ent),
                   "Expected service %d/%s alias 0 to be undefined, got %s\n",
                   i, wine_dbgstr_a(test_protos[j]),
                   wine_dbgstr_a(ent && ent->s_aliases ? ent->s_aliases[0] : NULL));
            }
        }
    }
}

START_TEST( protocol )
{
    WSADATA data;
    WORD version = MAKEWORD( 2, 2 );
 
    if (WSAStartup( version, &data )) return;

    test_WSAEnumProtocolsA();
    test_WSAEnumProtocolsW();
    test_getprotobyname();
    test_getprotobynumber();
    test_getservbyname();
    test_getservbyport();
}

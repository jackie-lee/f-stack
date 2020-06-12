/*
 * Copyright (c) 2010 Kip Macy. All rights reserved.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Derived in part from libplebnet's pn_syscall_wrapper.c.
 */

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>
#include <sys/pcpu.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ttycom.h>
#include <sys/filio.h>
#include <sys/sysproto.h>
#include <sys/fcntl.h>
#include <net/route.h>

#include <net/if.h>
#include <sys/sockio.h>

#include <machine/stdarg.h>

/* for sctp */
#include <sys/capsicum.h>
#include <sys/mbuf.h>
#include <netinet/sctp_uio.h>
/* for sctp */

#include "ff_api.h"
#include "ff_host_interface.h"

/* setsockopt/getsockopt define start */

#define LINUX_SOL_SOCKET      1

#define LINUX_SO_DEBUG        1
#define LINUX_SO_REUSEADDR    2
#define LINUX_SO_ERROR        4
#define LINUX_SO_DONTROUTE    5
#define LINUX_SO_BROADCAST    6
#define LINUX_SO_SNDBUF       7
#define LINUX_SO_RCVBUF       8
#define LINUX_SO_KEEPALIVE    9
#define LINUX_SO_OOBINLINE    10
#define LINUX_SO_LINGER       13
#define LINUX_SO_REUSEPORT    15
#define LINUX_SO_RCVLOWAT     18
#define LINUX_SO_SNDLOWAT     19
#define LINUX_SO_RCVTIMEO     20
#define LINUX_SO_SNDTIMEO     21
#define LINUX_SO_ACCEPTCONN   30
#define LINUX_SO_PROTOCOL     38


#define LINUX_IP_TOS        1
#define LINUX_IP_TTL        2
#define LINUX_IP_HDRINCL    3
#define LINUX_IP_OPTIONS    4

#define LINUX_IP_MULTICAST_IF       32
#define LINUX_IP_MULTICAST_TTL      33
#define LINUX_IP_MULTICAST_LOOP     34
#define LINUX_IP_ADD_MEMBERSHIP     35
#define LINUX_IP_DROP_MEMBERSHIP    36

#define LINUX_TCP_NODELAY     1
#define LINUX_TCP_MAXSEG      2
#define LINUX_TCP_KEEPIDLE    4
#define LINUX_TCP_KEEPINTVL   5
#define LINUX_TCP_KEEPCNT     6
#define LINUX_TCP_INFO        11
#define LINUX_TCP_MD5SIG      14

/* sctp option begin */

#define LINUX_SCTP_RTOINFO    0
#define LINUX_SCTP_ASSOCINFO  1
#define LINUX_SCTP_INITMSG    2
#define LINUX_SCTP_NODELAY    3               /* Get/set nodelay option. */
#define LINUX_SCTP_AUTOCLOSE  4
#define LINUX_SCTP_SET_PEER_PRIMARY_ADDR 5
#define LINUX_SCTP_PRIMARY_ADDR       6
#define LINUX_SCTP_ADAPTATION_LAYER   7
#define LINUX_SCTP_DISABLE_FRAGMENTS  8
#define LINUX_SCTP_PEER_ADDR_PARAMS   9
#define LINUX_SCTP_DEFAULT_SEND_PARAM 10
#define LINUX_SCTP_EVENTS     11
#define LINUX_SCTP_I_WANT_MAPPED_V4_ADDR 12   /* Turn on/off mapped v4 addresses  */
#define LINUX_SCTP_MAXSEG     13              /* Get/set maximum fragment. */
#define LINUX_SCTP_STATUS     14
#define LINUX_SCTP_GET_PEER_ADDR_INFO 15
#define LINUX_SCTP_DELAYED_ACK_TIME   16
#define LINUX_SCTP_DELAYED_ACK LINUX_SCTP_DELAYED_ACK_TIME
#define LINUX_SCTP_DELAYED_SACK LINUX_SCTP_DELAYED_ACK_TIME
#define LINUX_SCTP_CONTEXT    17
#define LINUX_SCTP_FRAGMENT_INTERLEAVE        18
#define LINUX_SCTP_PARTIAL_DELIVERY_POINT     19 /* Set/Get partial delivery point */
#define LINUX_SCTP_MAX_BURST  20              /* Set/Get max burst */
#define LINUX_SCTP_AUTH_CHUNK 21      /* Set only: add a chunk type to authenticate */
#define LINUX_SCTP_HMAC_IDENT 22
#define LINUX_SCTP_AUTH_KEY   23
#define LINUX_SCTP_AUTH_ACTIVE_KEY    24
#define LINUX_SCTP_AUTH_DELETE_KEY    25
#define LINUX_SCTP_PEER_AUTH_CHUNKS   26      /* Read only */
#define LINUX_SCTP_LOCAL_AUTH_CHUNKS  27      /* Read only */
#define LINUX_SCTP_GET_ASSOC_NUMBER   28      /* Read only */

/* Internal Socket Options. Some of the sctp library functions are
 * implemented using these socket options.
 */
#define LINUX_SCTP_SOCKOPT_BINDX_ADD  100     /* BINDX requests for adding addrs */
#define LINUX_SCTP_SOCKOPT_BINDX_REM  101     /* BINDX requests for removing addrs. */
#define LINUX_SCTP_SOCKOPT_PEELOFF    102     /* peel off association. */
/* Options 104-106 are deprecated and removed. Do not use this space */
#define LINUX_SCTP_SOCKOPT_CONNECTX_OLD       107     /* CONNECTX old requests. */
#define LINUX_SCTP_GET_PEER_ADDRS     108             /* Get all peer addresss. */
#define LINUX_SCTP_GET_LOCAL_ADDRS    109             /* Get all local addresss. */
#define LINUX_SCTP_SOCKOPT_CONNECTX   110             /* CONNECTX requests. */
#define LINUX_SCTP_SOCKOPT_CONNECTX3  111     /* CONNECTX requests (updated) */

/* SCTP socket option used to read per endpoint association statistics. */
#define LINUX_SCTP_GET_ASSOC_STATS    112      /* Read only */
/* sctp option end */

/* setsockopt/getsockopt define end */


/* ioctl define start */

#define LINUX_TIOCEXCL    0x540C
#define LINUX_TIOCNXCL    0x540D
#define LINUX_TIOCSCTTY   0x540E
#define LINUX_TIOCGPGRP   0x540F
#define LINUX_TIOCSPGRP   0x5410
#define LINUX_TIOCOUTQ    0x5411
#define LINUX_TIOCSTI     0x5412
#define LINUX_TIOCGWINSZ  0x5413
#define LINUX_TIOCSWINSZ  0x5414
#define LINUX_TIOCMGET    0x5415
#define LINUX_TIOCMBIS    0x5416
#define LINUX_TIOCMBIC    0x5417
#define LINUX_TIOCMSET    0x5418

#define LINUX_FIONREAD    0x541B
#define LINUX_TIOCCONS    0x541D
#define LINUX_TIOCPKT     0x5420
#define LINUX_FIONBIO     0x5421
#define LINUX_TIOCNOTTY   0x5422
#define LINUX_TIOCSETD    0x5423
#define LINUX_TIOCGETD    0x5424
#define LINUX_TIOCSBRK    0x5427
#define LINUX_TIOCCBRK    0x5428
#define LINUX_TIOCGSID    0x5429

#define LINUX_FIONCLEX    0x5450
#define LINUX_FIOCLEX     0x5451
#define LINUX_FIOASYNC    0x5452

#define LINUX_TIOCPKT_DATA          0
#define LINUX_TIOCPKT_FLUSHREAD     1
#define LINUX_TIOCPKT_FLUSHWRITE    2
#define LINUX_TIOCPKT_STOP          4
#define LINUX_TIOCPKT_START         8
#define LINUX_TIOCPKT_NOSTOP        16
#define LINUX_TIOCPKT_DOSTOP        32
#define LINUX_TIOCPKT_IOCTL         64

#define LINUX_SIOCGIFCONF     0x8912
#define LINUX_SIOCGIFFLAGS    0x8913
#define LINUX_SIOCSIFFLAGS    0x8914
#define LINUX_SIOCGIFADDR     0x8915
#define LINUX_SIOCSIFADDR     0x8916
#define LINUX_SIOCGIFDSTADDR  0x8917
#define LINUX_SIOCSIFDSTADDR  0x8918
#define LINUX_SIOCGIFBRDADDR  0x8919
#define LINUX_SIOCSIFBRDADDR  0x891a
#define LINUX_SIOCGIFNETMASK  0x891b
#define LINUX_SIOCSIFNETMASK  0x891c
#define LINUX_SIOCGIFMETRIC   0x891d
#define LINUX_SIOCSIFMETRIC   0x891e
#define LINUX_SIOCGIFMTU      0x8921
#define LINUX_SIOCSIFMTU      0x8922
#define LINUX_SIOCSIFNAME     0x8923
#define LINUX_SIOCADDMULTI    0x8931
#define LINUX_SIOCDELMULTI    0x8932
#define LINUX_SIOCGIFINDEX    0x8933
#define LINUX_SIOCDIFADDR     0x8936

/* ioctl define end */


extern int sendit(struct thread *td, int s, struct msghdr *mp, int flags);

/* for sctp */
int linux2freebsd_opt(int level, int optname);

static long
linux2freebsd_ioctl(unsigned long request)
{
    switch(request) {
        case LINUX_TIOCEXCL:
            return TIOCEXCL;
        case LINUX_TIOCNXCL:
            return TIOCNXCL;
        case LINUX_TIOCSCTTY:
            return TIOCSCTTY;
        case LINUX_TIOCGPGRP:
            return TIOCGPGRP;
        case LINUX_TIOCSPGRP:
            return TIOCSPGRP;
        case LINUX_TIOCOUTQ:
            return TIOCOUTQ;
        case LINUX_TIOCSTI:
            return TIOCSTI;
        case LINUX_TIOCGWINSZ:
            return TIOCGWINSZ;
        case LINUX_TIOCSWINSZ:
            return TIOCSWINSZ;
        case LINUX_TIOCMGET:
            return TIOCMGET;
        case LINUX_TIOCMBIS:
            return TIOCMBIS;
        case LINUX_TIOCMBIC:
            return TIOCMBIC;
        case LINUX_TIOCMSET:
            return TIOCMSET;
        case LINUX_FIONREAD:
            return FIONREAD;
        case LINUX_TIOCCONS:
            return TIOCCONS;
        case LINUX_TIOCPKT:
            return TIOCPKT;
        case LINUX_FIONBIO:
            return FIONBIO;
        case LINUX_TIOCNOTTY:
            return TIOCNOTTY;
        case LINUX_TIOCSETD:
            return TIOCSETD;
        case LINUX_TIOCGETD:
            return TIOCGETD;
        case LINUX_TIOCSBRK:
            return TIOCSBRK;
        case LINUX_TIOCCBRK:
            return TIOCCBRK;
        case LINUX_TIOCGSID:
            return TIOCGSID;
        case LINUX_FIONCLEX:
            return FIONCLEX;
        case LINUX_FIOCLEX:
            return FIOCLEX;
        case LINUX_FIOASYNC:
            return FIOASYNC;
        case LINUX_TIOCPKT_DATA:
            return TIOCPKT_DATA;
        case LINUX_TIOCPKT_FLUSHREAD:
            return TIOCPKT_FLUSHREAD;
        case LINUX_TIOCPKT_FLUSHWRITE:
            return TIOCPKT_FLUSHWRITE;
        case LINUX_TIOCPKT_STOP:
            return TIOCPKT_STOP;
        case LINUX_TIOCPKT_START:
            return TIOCPKT_START;
        case LINUX_TIOCPKT_NOSTOP:
            return TIOCPKT_NOSTOP;
        case LINUX_TIOCPKT_DOSTOP:
            return TIOCPKT_DOSTOP;
        case LINUX_TIOCPKT_IOCTL:
            return TIOCPKT_IOCTL;
        case LINUX_SIOCGIFCONF:
            return SIOCGIFCONF;
        case LINUX_SIOCGIFFLAGS:
            return SIOCGIFFLAGS;
        case LINUX_SIOCSIFFLAGS:
            return SIOCSIFFLAGS;
        case LINUX_SIOCGIFADDR:
            return SIOCGIFADDR;
        case LINUX_SIOCSIFADDR:
            return SIOCSIFADDR;
        case LINUX_SIOCGIFDSTADDR:
            return SIOCGIFDSTADDR;
        case LINUX_SIOCSIFDSTADDR:
            return SIOCSIFDSTADDR;
        case LINUX_SIOCGIFBRDADDR:
            return SIOCGIFBRDADDR;
        case LINUX_SIOCSIFBRDADDR:
            return SIOCSIFBRDADDR;
        case LINUX_SIOCGIFNETMASK:
            return SIOCGIFNETMASK;
        case LINUX_SIOCSIFNETMASK:
            return SIOCSIFNETMASK;
        case LINUX_SIOCGIFMETRIC:
            return SIOCGIFMETRIC;
        case LINUX_SIOCSIFMETRIC:
            return SIOCSIFMETRIC;
        case LINUX_SIOCGIFMTU:
            return SIOCGIFMTU;
        case LINUX_SIOCSIFMTU:
            return SIOCSIFMTU;
        case LINUX_SIOCSIFNAME:
            return SIOCSIFNAME;
        case LINUX_SIOCADDMULTI:
            return SIOCADDMULTI;
        case LINUX_SIOCDELMULTI:
            return SIOCDELMULTI;
        case LINUX_SIOCGIFINDEX:
            return SIOCGIFINDEX;
        case LINUX_SIOCDIFADDR:
            return SIOCDIFADDR;
        default:
            return -1;
    }
}

static int
so_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_SO_DEBUG:
            return SO_DEBUG;
        case LINUX_SO_REUSEADDR:
            return SO_REUSEADDR;
        case LINUX_SO_ERROR:
            return SO_ERROR;
        case LINUX_SO_DONTROUTE:
            return SO_DONTROUTE;
        case LINUX_SO_BROADCAST:
            return SO_BROADCAST;
        case LINUX_SO_SNDBUF:
            return SO_SNDBUF;
        case LINUX_SO_RCVBUF:
            return SO_RCVBUF;
        case LINUX_SO_KEEPALIVE:
            return SO_KEEPALIVE;
        case LINUX_SO_OOBINLINE:
            return SO_OOBINLINE;
        case LINUX_SO_LINGER:
            return SO_LINGER;
        case LINUX_SO_REUSEPORT:
            return SO_REUSEPORT;
        case LINUX_SO_RCVLOWAT:
            return SO_RCVLOWAT;
        case LINUX_SO_SNDLOWAT:
            return SO_SNDLOWAT;
        case LINUX_SO_RCVTIMEO:
            return SO_RCVTIMEO;
        case LINUX_SO_SNDTIMEO:
            return SO_SNDTIMEO;
        case LINUX_SO_ACCEPTCONN:
            return SO_ACCEPTCONN;
        case LINUX_SO_PROTOCOL:
            return SO_PROTOCOL;
        default:
            return -1;
    }
}

static int
ip_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_IP_TOS:
            return IP_TOS;
        case LINUX_IP_TTL:
            return IP_TTL;
        case LINUX_IP_HDRINCL:
            return IP_HDRINCL;
        case LINUX_IP_OPTIONS:
            return IP_OPTIONS;
        case LINUX_IP_MULTICAST_IF:
            return IP_MULTICAST_IF;
        case LINUX_IP_MULTICAST_TTL:
            return IP_MULTICAST_TTL;
        case LINUX_IP_MULTICAST_LOOP:
            return IP_MULTICAST_LOOP;
        case LINUX_IP_ADD_MEMBERSHIP:
            return IP_ADD_MEMBERSHIP;
        case LINUX_IP_DROP_MEMBERSHIP:
            return IP_DROP_MEMBERSHIP;
        default:
            return optname;
    }
}

static int
tcp_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_TCP_NODELAY:
            return TCP_NODELAY;
        case LINUX_TCP_MAXSEG:
            return TCP_MAXSEG;
        case LINUX_TCP_KEEPIDLE:
            return TCP_KEEPIDLE;
        case LINUX_TCP_KEEPINTVL:
            return TCP_KEEPINTVL;
        case LINUX_TCP_KEEPCNT:
            return TCP_KEEPCNT;
        case LINUX_TCP_INFO:
            return TCP_INFO;
        case LINUX_TCP_MD5SIG:
            return TCP_MD5SIG;
        default:
            return -1;
    }
}

static int
sctp_opt_convert(int optname)
{
    switch(optname) {
        case LINUX_SCTP_RTOINFO:
            return SCTP_RTOINFO;
        case LINUX_SCTP_ASSOCINFO:
            return SCTP_ASSOCINFO;
        case LINUX_SCTP_INITMSG:
            return SCTP_INITMSG;
        case LINUX_SCTP_NODELAY:
            return SCTP_NODELAY;
        case LINUX_SCTP_AUTOCLOSE:
            return SCTP_AUTOCLOSE;
        case LINUX_SCTP_SET_PEER_PRIMARY_ADDR:
            return SCTP_SET_PEER_PRIMARY_ADDR;
        case LINUX_SCTP_PRIMARY_ADDR:
            return SCTP_PRIMARY_ADDR;
        case LINUX_SCTP_ADAPTATION_LAYER:
            return SCTP_ADAPTATION_LAYER;
        case LINUX_SCTP_DISABLE_FRAGMENTS:
            return SCTP_DISABLE_FRAGMENTS;
        case LINUX_SCTP_PEER_ADDR_PARAMS:
            return SCTP_PEER_ADDR_PARAMS;
        case LINUX_SCTP_DEFAULT_SEND_PARAM:
            return SCTP_DEFAULT_SEND_PARAM;
        case LINUX_SCTP_EVENTS:
            return SCTP_EVENTS;
        case LINUX_SCTP_I_WANT_MAPPED_V4_ADDR:
            return SCTP_I_WANT_MAPPED_V4_ADDR;
        case LINUX_SCTP_MAXSEG:
            return SCTP_MAXSEG;
        case LINUX_SCTP_STATUS:
            return SCTP_STATUS;
        case LINUX_SCTP_GET_PEER_ADDR_INFO:
            return SCTP_GET_PEER_ADDR_INFO;
/*
        case LINUX_SCTP_DELAYED_ACK_TIME:
            return SCTP_DELAYED_ACK_TIME;
        case LINUX_SCTP_DELAYED_ACK:
            return SCTP_DELAYED_ACK;
*/
        case LINUX_SCTP_DELAYED_SACK:
            return SCTP_DELAYED_SACK;
        case LINUX_SCTP_CONTEXT:
            return SCTP_CONTEXT;
        case LINUX_SCTP_FRAGMENT_INTERLEAVE:
            return SCTP_FRAGMENT_INTERLEAVE;
        case LINUX_SCTP_PARTIAL_DELIVERY_POINT:
            return SCTP_PARTIAL_DELIVERY_POINT;
        case LINUX_SCTP_MAX_BURST:
            return SCTP_MAX_BURST;
        case LINUX_SCTP_AUTH_CHUNK:
            return SCTP_AUTH_CHUNK;
        case LINUX_SCTP_HMAC_IDENT:
            return SCTP_HMAC_IDENT;
        case LINUX_SCTP_AUTH_KEY:
            return SCTP_AUTH_KEY;
        case LINUX_SCTP_AUTH_ACTIVE_KEY:
            return SCTP_AUTH_ACTIVE_KEY;
        case LINUX_SCTP_AUTH_DELETE_KEY:
            return SCTP_AUTH_DELETE_KEY;
        case LINUX_SCTP_PEER_AUTH_CHUNKS:
            return SCTP_PEER_AUTH_CHUNKS;
        case LINUX_SCTP_LOCAL_AUTH_CHUNKS:
            return SCTP_LOCAL_AUTH_CHUNKS;
        case LINUX_SCTP_GET_ASSOC_NUMBER:
            return SCTP_GET_ASSOC_NUMBER;
/*
        case LINUX_SCTP_SOCKOPT_BINDX_ADD:
            return SCTP_SOCKOPT_BINDX_ADD;
        case LINUX_SCTP_SOCKOPT_BINDX_REM:
            return SCTP_SOCKOPT_BINDX_REM;
        case LINUX_SCTP_SOCKOPT_PEELOFF:
            return SCTP_SOCKOPT_PEELOFF;
        case LINUX_SCTP_SOCKOPT_CONNECTX_OLD:
            return SCTP_SOCKOPT_CONNECTX_OLD;
        case LINUX_SCTP_GET_PEER_ADDRS:
            return SCTP_GET_PEER_ADDRS;
        case LINUX_SCTP_GET_LOCAL_ADDRS:
            return SCTP_GET_LOCAL_ADDRS;
        case LINUX_SCTP_SOCKOPT_CONNECTX:
            return SCTP_SOCKOPT_CONNECTX;
        case LINUX_SCTP_SOCKOPT_CONNECTX3:
            return SCTP_SOCKOPT_CONNECTX3;
        case LINUX_SCTP_GET_ASSOC_STATS:
            return SCTP_GET_ASSOC_STATS;
*/
        default:
            return optname;
    }
}

int
linux2freebsd_opt(int level, int optname)
{
    switch(level) {
        case SOL_SOCKET:
            return so_opt_convert(optname);
        case IPPROTO_IP:
            return ip_opt_convert(optname);
        case IPPROTO_TCP:
            return tcp_opt_convert(optname);
		/* for sctp */
        case IPPROTO_SCTP:
            return sctp_opt_convert(optname);
        default:
            return -1;
    }
}

static void
linux2freebsd_sockaddr(const struct linux_sockaddr *linux,
    socklen_t addrlen, struct sockaddr *freebsd)
{
    if (linux == NULL) {
        return;
    }

    /* #linux and #freebsd may point to the same address */
    freebsd->sa_family = linux->sa_family;
    freebsd->sa_len = addrlen;

    bcopy(linux->sa_data, freebsd->sa_data, addrlen - sizeof(linux->sa_family));
}

static void
freebsd2linux_sockaddr(struct linux_sockaddr *linux,
    struct sockaddr *freebsd)
{
    if (linux == NULL) {
        return;
    }

    linux->sa_family = freebsd->sa_family;

    bcopy(freebsd->sa_data, linux->sa_data, freebsd->sa_len - sizeof(linux->sa_family));
}

/* for sctp */
static void freebsd2linux_sctp_sndrcvinfo(struct linux_sctp_sndrcvinfo *linux,
    struct sctp_sndrcvinfo *freebsd)
{
    linux->sinfo_stream = freebsd->sinfo_stream;
    linux->sinfo_ssn = freebsd->sinfo_ssn;
    linux->sinfo_flags = freebsd->sinfo_flags;
    linux->sinfo_ppid = freebsd->sinfo_ppid;
    linux->sinfo_context = freebsd->sinfo_context;
    linux->sinfo_timetolive = freebsd->sinfo_timetolive;
    linux->sinfo_tsn = freebsd->sinfo_tsn;
    linux->sinfo_cumtsn = freebsd->sinfo_cumtsn;
    linux->sinfo_assoc_id = freebsd->sinfo_assoc_id;
}

int
ff_socket(int domain, int type, int protocol)
{
    int rc;
    struct socket_args sa;
    sa.domain = domain;
    sa.type = type;
    sa.protocol = protocol;
    if ((rc = sys_socket(curthread, &sa)))
        goto kern_fail;

    return curthread->td_retval[0];
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen)
{
    int rc;
    if (level == LINUX_SOL_SOCKET)
        level = SOL_SOCKET;

    optname = linux2freebsd_opt(level, optname);
    if (optname < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    if ((rc = kern_getsockopt(curthread, s, level, optname,
            optval, UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getsockopt_freebsd(int s, int level, int optname,
    void *optval, socklen_t *optlen)
{
    int rc;

    if ((rc = kern_getsockopt(curthread, s, level, optname,
            optval, UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen)
{
    int rc;

    if (level == LINUX_SOL_SOCKET)
        level = SOL_SOCKET;

    optname = linux2freebsd_opt(level, optname);
    if (optname < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    if ((rc = kern_setsockopt(curthread, s, level, optname,
            __DECONST(void *, optval), UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_setsockopt_freebsd(int s, int level, int optname,
    const void *optval, socklen_t optlen)
{
    int rc;

    if ((rc = kern_setsockopt(curthread, s, level, optname,
            __DECONST(void *, optval), UIO_USERSPACE, optlen)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_ioctl(int fd, unsigned long request, ...)
{
    int rc;
    va_list ap;
    caddr_t argp;

    long req = linux2freebsd_ioctl(request);
    if (req < 0) {
        rc = EINVAL;
        goto kern_fail;
    }

    va_start(ap, request);

    argp = va_arg(ap, caddr_t);
    va_end(ap);
    if ((rc = kern_ioctl(curthread, fd, req, argp)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_ioctl_freebsd(int fd, unsigned long request, ...)
{
    int rc;
    va_list ap;
    caddr_t argp;

    va_start(ap, request);

    argp = va_arg(ap, caddr_t);
    va_end(ap);
    if ((rc = kern_ioctl(curthread, fd, request, argp)))
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_close(int fd)
{
    int rc;

    if ((rc = kern_close(curthread, fd))) 
        goto kern_fail;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_read(int fd, void *buf, size_t nbytes)
{
    struct uio auio;
    struct iovec aiov;
    int rc;
    
    if (nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    aiov.iov_base = buf;
    aiov.iov_len = nbytes;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_SYSSPACE;
    if ((rc = kern_readv(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_readv(int fd, const struct iovec *iov, int iovcnt)
{
    struct uio auio;
    int rc, len, i;

    len = 0;
    for (i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    auio.uio_iov = __DECONST(struct iovec *, iov);
    auio.uio_iovcnt = iovcnt;
    auio.uio_resid = len;
    auio.uio_segflg = UIO_SYSSPACE;

    if ((rc = kern_readv(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_readm(int fd, struct mbuf **mp)
{
    int rc;
    int flags = MSG_DONTWAIT;
    struct file *fp;
    cap_rights_t rights;
    struct mbuf *m;
    struct uio auio = {0};
    ssize_t cnt = 0;

    if (mp == NULL) {
        rc = EINVAL;
        goto kern_fail;
    }

    auio.uio_resid = 2048;

    rc = fget_read(curthread, fd, cap_rights_init(&rights, CAP_READ), &fp);
    if (rc) {
        goto kern_fail;
    }
    rc = soreceive((struct socket *)fp->f_data, 0, &auio, mp, 0, &flags);
    fdrop(fp, curthread);    
    if (rc) {
        goto kern_fail;
    }

    return m_length(*mp, NULL);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_write(int fd, const void *buf, size_t nbytes)
{
    struct uio auio;
    struct iovec aiov;
    int rc;

    if (nbytes > INT_MAX) {
        rc = EINVAL;
        goto kern_fail;
    }

    aiov.iov_base = (void *)(uintptr_t)buf;
    aiov.iov_len = nbytes;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_SYSSPACE;
    if ((rc = kern_writev(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct uio auio;
    int i, rc, len;

    len = 0;
    for (i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    auio.uio_iov = __DECONST(struct iovec *, iov);
    auio.uio_iovcnt = iovcnt;
    auio.uio_resid = len;
    auio.uio_segflg = UIO_SYSSPACE;
    if ((rc = kern_writev(curthread, fd, &auio)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_writem(int fd, struct mbuf *m)
{
    int i, rc, len;
    struct file *fp;
    cap_rights_t rights;
    struct socket *so;
    ssize_t cnt;

    cnt = m->m_pkthdr.len;
    
    rc = fget_write(curthread, fd, cap_rights_init(&rights, CAP_WRITE), &fp);
    if (rc) {
        goto kern_fail;
    }

    so = (struct socket *)fp->f_data;
    rc = sosend(so, 0, NULL, m, 0, 0, curthread);
    fdrop(fp, curthread);
    
    if (rc) {
        goto kern_fail;
    }

    return (cnt);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_send(int s, const void *buf, size_t len, int flags)
{
    return (ff_sendto(s, buf, len, flags, NULL, 0));
}

ssize_t
ff_sendto(int s, const void *buf, size_t len, int flags,
         const struct linux_sockaddr *to, socklen_t tolen)
{
    struct msghdr msg;
    struct iovec aiov;
    int rc;

    struct sockaddr_storage bsdaddr;
    struct sockaddr *pf = (struct sockaddr *)&bsdaddr;

    if (to) {
        linux2freebsd_sockaddr(to, tolen, pf);
    } else {
        pf = NULL;
    }

    msg.msg_name = pf;
    msg.msg_namelen = tolen;
    msg.msg_iov = &aiov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    aiov.iov_base = __DECONST(void *, buf);
    aiov.iov_len = len;
    if ((rc = sendit(curthread, s, &msg, flags)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_sendmsg(int s, const struct msghdr *msg, int flags)
{
    int rc;
    struct sockaddr_storage freebsd_sa;
    void *linux_sa = msg->msg_name;

    if (linux_sa != NULL) {
        linux2freebsd_sockaddr(linux_sa,
            sizeof(struct linux_sockaddr), (struct sockaddr *)&freebsd_sa);
        __DECONST(struct msghdr *, msg)->msg_name = &freebsd_sa;
    }

    rc = sendit(curthread, s, __DECONST(struct msghdr *, msg), flags);

    __DECONST(struct msghdr *, msg)->msg_name = linux_sa;

    if (rc)
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}


ssize_t
ff_recv(int s, void *buf, size_t len, int flags)
{
    return (ff_recvfrom(s, buf, len, flags, NULL, 0));
}

ssize_t
ff_recvfrom(int s, void *buf, size_t len, int flags,
    struct linux_sockaddr *from, socklen_t *fromlen)
{
    struct msghdr msg;
    struct iovec aiov;
    int rc;
    struct sockaddr_storage bsdaddr;

    if (fromlen != NULL)
        msg.msg_namelen = *fromlen;
    else
        msg.msg_namelen = 0;

    msg.msg_name = &bsdaddr;
    msg.msg_iov = &aiov;
    msg.msg_iovlen = 1;
    aiov.iov_base = buf;
    aiov.iov_len = len;
    msg.msg_control = 0;
    msg.msg_flags = flags;
    if ((rc = kern_recvit(curthread, s, &msg, UIO_SYSSPACE, NULL)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    if (fromlen != NULL)
        *fromlen = msg.msg_namelen;

    if (from)
        freebsd2linux_sockaddr(from, (struct sockaddr *)&bsdaddr);

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

ssize_t
ff_recvmsg(int s, struct msghdr *msg, int flags)
{
    int rc, oldflags;

    oldflags = msg->msg_flags;
    msg->msg_flags = flags;

    if ((rc = kern_recvit(curthread, s, msg, UIO_SYSSPACE, NULL))) {
        msg->msg_flags = oldflags;
        goto kern_fail;
    }
    rc = curthread->td_retval[0];

    freebsd2linux_sockaddr(msg->msg_name, msg->msg_name);

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_fcntl(int fd, int cmd, ...)
{
    int rc;
    va_list ap;
    uintptr_t argp;

    va_start(ap, cmd);

    argp = va_arg(ap, uintptr_t);
    va_end(ap);    

    if ((rc = kern_fcntl(curthread, fd, cmd, argp)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_accept(int s, struct linux_sockaddr * addr,
    socklen_t * addrlen)
{
    int rc;
    struct file *fp;
    struct sockaddr *pf = NULL;
    socklen_t socklen = sizeof(struct sockaddr_storage);

    if ((rc = kern_accept(curthread, s, &pf, &socklen, &fp)))
        goto kern_fail;

    rc = curthread->td_retval[0];
    fdrop(fp, curthread);

    if (addr && pf)
        freebsd2linux_sockaddr(addr, pf);

    if (addrlen)
        *addrlen = pf->sa_len;
    
    if(pf != NULL)
        free(pf, M_SONAME);
    return (rc);
    
kern_fail:
    if(pf != NULL)
        free(pf, M_SONAME);
    ff_os_errno(rc);
    return (-1);
}

int
ff_listen(int s, int backlog)
{
    int rc;
    struct listen_args la = {
        .s = s,
        .backlog = backlog,
    };
    if ((rc = sys_listen(curthread, &la)))
        goto kern_fail;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen)
{
    int rc;    
    struct sockaddr_storage bsdaddr;
    linux2freebsd_sockaddr(addr, addrlen, (struct sockaddr *)&bsdaddr);

    if ((rc = kern_bindat(curthread, AT_FDCWD, s, (struct sockaddr *)&bsdaddr)))
        goto kern_fail;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen)
{
    int rc;
    struct sockaddr_storage bsdaddr;
    linux2freebsd_sockaddr(name, namelen, (struct sockaddr *)&bsdaddr);

    if ((rc = kern_connectat(curthread, AT_FDCWD, s, (struct sockaddr *)&bsdaddr)))
        goto kern_fail;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_getpeername(int s, struct linux_sockaddr * name,
    socklen_t *namelen)
{
    int rc;
    struct sockaddr *pf = NULL;

    if ((rc = kern_getpeername(curthread, s, &pf, namelen)))
        goto kern_fail;

    if (name && pf)
        freebsd2linux_sockaddr(name, pf);

    if(pf != NULL)
        free(pf, M_SONAME);
    return (rc);
    
kern_fail:
    if(pf != NULL)
        free(pf, M_SONAME);
    ff_os_errno(rc);
    return (-1);
}

int
ff_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen)
{
    int rc;
    struct sockaddr *pf = NULL;

    if ((rc = kern_getsockname(curthread, s, &pf, namelen)))
        goto kern_fail;

    if (name && pf)
        freebsd2linux_sockaddr(name, pf);

    if(pf != NULL)
        free(pf, M_SONAME);
    return (rc);

kern_fail:
    if(pf != NULL)
        free(pf, M_SONAME);
    ff_os_errno(rc);
    return (-1);
}

int    
ff_shutdown(int s, int how)
{
    int rc;

    struct shutdown_args sa = {
        .s = s,
        .how = how,
    };
    if ((rc = sys_shutdown(curthread, &sa)))
        goto kern_fail;

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
         const void *newp, size_t newlen)
{
    int rc;
    size_t retval;

    rc = userland_sysctl(curthread, __DECONST(int *, name), namelen, oldp, oldlenp, 
        1, __DECONST(void *, newp), newlen, &retval, 0);
    if (rc)
        goto kern_fail;
    if (oldlenp)
        *oldlenp = retval;
    return (0);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)

{
    int rc;

    rc = kern_select(curthread, nfds, readfds, writefds, exceptfds, timeout, 64);
    if (rc)
        goto kern_fail;
    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);

}

int
ff_poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
    int rc;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    if ((rc = kern_poll(curthread, fds, nfds, &ts, NULL)))
        goto kern_fail;
    rc = curthread->td_retval[0];
    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_kqueue(void)
{
    int rc;
    if ((rc = kern_kqueue(curthread, 0, NULL)))
        goto kern_fail;

    rc = curthread->td_retval[0];
    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

struct sys_kevent_args {
    int fd;
    const struct kevent *changelist;
    int nchanges;
    void *eventlist;
    int nevents;
    const struct timespec *timeout;
    void (*do_each)(void **, struct kevent *);
};

static int
kevent_copyout(void *arg, struct kevent *kevp, int count)
{
    int i;
    struct kevent *ke;
    struct sys_kevent_args *uap;

    uap = (struct sys_kevent_args *)arg;

    if (!uap->do_each) {
        bcopy(kevp, uap->eventlist, count * sizeof *kevp);
        uap->eventlist = (void *)((struct kevent *)(uap->eventlist) + count);

    } else {
        for (ke = kevp, i = 0; i < count; i++, ke++) {
            uap->do_each(&(uap->eventlist), ke);
        }
    }

    return (0);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
kevent_copyin(void *arg, struct kevent *kevp, int count)
{
    struct sys_kevent_args *uap;

    uap = (struct sys_kevent_args *)arg;
    bcopy(uap->changelist, kevp, count * sizeof *kevp);

    uap->changelist += count;

    return (0);
}

int
ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges, 
    void *eventlist, int nevents, const struct timespec *timeout, 
    void (*do_each)(void **, struct kevent *))
{
    int rc;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    struct sys_kevent_args ska = {
        kq,
        changelist,
        nchanges,
        eventlist,
        nevents,
        &ts,
        do_each
    };

    struct kevent_copyops k_ops = {
        &ska,
        kevent_copyout,
        kevent_copyin
    };

    if ((rc = kern_kevent(curthread, kq, nchanges, nevents, &k_ops, 
            &ts)))
        goto kern_fail;

    rc = curthread->td_retval[0];
    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_kevent(int kq, const struct kevent *changelist, int nchanges, 
    struct kevent *eventlist, int nevents, const struct timespec *timeout)
{
    return ff_kevent_do_each(kq, changelist, nchanges, eventlist, nevents, timeout, NULL);
}

int
ff_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    long nsec;
    ff_get_current_time(&(tv->tv_sec), &nsec);
    tv->tv_usec = nsec/1000;
    return 0;
}

int
ff_dup(int oldfd)
{
    int rc;
    struct dup_args da = {
        .fd = oldfd,
    };
    if ((rc = sys_dup(curthread, &da)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_dup2(int oldfd, int newfd)
{
    int rc;
    struct dup2_args da = {
        .from = oldfd,
        .to = newfd
    };
    if ((rc = sys_dup2(curthread, &da)))
        goto kern_fail;

    rc = curthread->td_retval[0];

    return (rc);
kern_fail:
    ff_os_errno(rc);
    return (-1);
}

int
ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
    struct linux_sockaddr *dst, struct linux_sockaddr *gw,
    struct linux_sockaddr *netmask)

{
    struct sockaddr_storage sa_gw, sa_dst, sa_nm;
    struct sockaddr *psa_gw, *psa_dst, *psa_nm;
    int rtreq, rtflag;
    int rc;

    switch (req) {
        case FF_ROUTE_ADD:
            rtreq = RTM_ADD;
            break;
        case FF_ROUTE_DEL:
            rtreq = RTM_DELETE;
            break;
        case FF_ROUTE_CHANGE:
            rtreq = RTM_CHANGE;
            break;
        default:
            rc = EINVAL;
            goto kern_fail;
    }

    switch (flag) {
        case FF_RTF_HOST:
            rtflag = RTF_HOST;
            break;
        case FF_RTF_GATEWAY:
            rtflag = RTF_GATEWAY;
            break;
        default:
            rc = EINVAL;
            goto kern_fail;
    };

    if (gw != NULL) {
        psa_gw = (struct sockaddr *)&sa_gw;
        linux2freebsd_sockaddr(gw, sizeof(*gw), psa_gw);
    } else {
        psa_gw = NULL;
    }

    if (dst != NULL) {
        psa_dst = (struct sockaddr *)&sa_dst;
        linux2freebsd_sockaddr(dst, sizeof(*dst), psa_dst);
    } else {
        psa_dst = NULL;
    }

    if (netmask != NULL) {
        psa_nm = (struct sockaddr *)&sa_nm;
        linux2freebsd_sockaddr(netmask, sizeof(*netmask), psa_nm);
    } else {
        psa_nm = NULL;
    }

    rc = rtrequest_fib(rtreq, psa_dst, psa_gw, psa_nm, rtflag,
        NULL, RT_DEFAULT_FIB);

    if (rc != 0)
        goto kern_fail;

    return (rc);

kern_fail:
    ff_os_errno(rc);
    return (-1);
}

#define SCTP_CONTROL_VEC_SIZE_RCV  16384

int
ff_sctp_recvmsg(int s, void *data, size_t len,
    struct linux_sockaddr *from, socklen_t *fromlen,
    struct linux_sctp_sndrcvinfo *sinfo, int *msg_flags)
{
    int rc;
    struct iovec iov;
    struct sockaddr sa_from;
    struct sctp_sndrcvinfo usi;
    struct sctp_generic_recvmsg_args ua;

    iov.iov_base = data;
    iov.iov_len = len;

    ua.sd = s;
    ua.mp = NULL;
    ua.iov = &iov;
    ua.iovlen = 1;
    ua.from = &sa_from;
    ua.fromlenaddr = fromlen;
    ua.sinfo = &usi;
    ua.msg_flags = msg_flags;

    rc = sys_sctp_generic_recvmsg(curthread, &ua);
    if (rc) {
        ff_os_errno(rc);
        return -1;
    }

    if (from != NULL)
        freebsd2linux_sockaddr(from, &sa_from);

    if (sinfo)
        freebsd2linux_sctp_sndrcvinfo(sinfo, &usi);

    return curthread->td_retval[0];
}

int
ff_sctp_recvm(int s, struct mbuf **mp,
    struct linux_sockaddr *from, socklen_t *fromlen,
    struct linux_sctp_sndrcvinfo *sinfo, int *msg_flags)
{
    int rc;
    struct sockaddr sa_from;
    struct sctp_sndrcvinfo usi;
    struct sctp_generic_recvmsg_args ua;

    ua.sd = s;
    ua.mp = mp;
    ua.iov = NULL;
    ua.iovlen = 0;
    ua.from = &sa_from;
    ua.fromlenaddr = fromlen;
    ua.sinfo = &usi;
    ua.msg_flags = msg_flags;
    
	rc = sys_sctp_generic_recvmsg(curthread, &ua);
    if (rc) {
        ff_os_errno(rc);
        return -1;
    }

    if (from != NULL)
        freebsd2linux_sockaddr(from, &sa_from);

    if (sinfo)
        freebsd2linux_sctp_sndrcvinfo(sinfo, &usi);
    
    return curthread->td_retval[0];
}
int
ff_sctp_sendmsg(int s, const void *data, size_t len,
    const struct sockaddr *to, socklen_t tolen, uint32_t ppid,
    uint32_t flags, uint16_t stream_no, uint32_t timetolive,
    uint32_t context)
{
//#ifdef SYS_sctp_generic_sendmsg
#if 1
    int rc;
	struct sctp_sndrcvinfo sinfo;
    struct sctp_generic_sendmsg_args ua;

	memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo.sinfo_ppid = ppid;
	sinfo.sinfo_flags = flags;
	sinfo.sinfo_stream = stream_no;
	sinfo.sinfo_timetolive = timetolive;
	sinfo.sinfo_context = context;
	sinfo.sinfo_assoc_id = 0;

    ua.sd = s;
    ua.m = NULL;
    ua.msg = __DECONST(caddr_t, data);
    ua.mlen = len;
    ua.to = __DECONST(caddr_t, to);
    ua.tolen = tolen;
    ua.sinfo = &sinfo;
    ua.flags = flags;
    
	rc = sys_sctp_generic_sendmsg(curthread, &ua);
    if (rc) {
        ff_os_errno(rc);
        return -1;
    }

    return curthread->td_retval[0];
#else
    int rc;
	struct msghdr msg;
	struct sctp_sndrcvinfo *sinfo;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct cmsghdr *cmsg;
	struct sockaddr *who = NULL;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	}     addr;

	if ((tolen > 0) &&
	    ((to == NULL) || (tolen < sizeof(struct sockaddr)))) {
		rc = ff_EINVAL;
		goto kern_fail;
	}
	if ((to != NULL) && (tolen > 0)) {
		switch (to->sa_family) {
		case AF_INET:
			if (tolen != sizeof(struct sockaddr_in)) {
				rc = ff_EINVAL;
				return (-1);
			}
			if ((to->sa_len > 0) &&
			    (to->sa_len != sizeof(struct sockaddr_in))) {
				rc = ff_EINVAL;
				goto kern_fail;
			}
			memcpy(&addr, to, sizeof(struct sockaddr_in));
			addr.in.sin_len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			if (tolen != sizeof(struct sockaddr_in6)) {
				rc = ff_EINVAL;
				goto kern_fail;
			}
			if ((to->sa_len > 0) &&
			    (to->sa_len != sizeof(struct sockaddr_in6))) {
				rc = ff_EINVAL;
				goto kern_fail;
			}
			memcpy(&addr, to, sizeof(struct sockaddr_in6));
			addr.in6.sin6_len = sizeof(struct sockaddr_in6);
			break;
		default:
			rc = ff_EAFNOSUPPORT;
			goto kern_fail;
		}
		who = (struct sockaddr *)&addr;
	}
	iov.iov_base = __DECONST(void *, data);
	iov.iov_len = len;

	if (who) {
		msg.msg_name = (caddr_t)who;
		msg.msg_namelen = who->sa_len;
	} else {
		msg.msg_name = (caddr_t)NULL;
		msg.msg_namelen = 0;
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
	msg.msg_flags = 0;
	cmsg = (struct cmsghdr *)cmsgbuf;
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo->sinfo_stream = stream_no;
	sinfo->sinfo_ssn = 0;
	sinfo->sinfo_flags = flags;
	sinfo->sinfo_ppid = ppid;
	sinfo->sinfo_context = context;
	sinfo->sinfo_assoc_id = 0;
	sinfo->sinfo_timetolive = timetolive;
	return (ff_sendmsg(s, &msg, 0));

kern_fail:
    ff_os_errno(rc);
    return (-1);
#endif
}

int
ff_sctp_sendm(int s, const struct mbuf *m,
    const struct linux_sockaddr *to, socklen_t tolen, uint32_t ppid,
    uint32_t flags, uint16_t stream_no, uint32_t timetolive,
    uint32_t context)
{
    int rc;
    struct sctp_sndrcvinfo sinfo;
    struct sctp_generic_sendmsg_args ua;

    memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
    sinfo.sinfo_ppid = ppid;
    sinfo.sinfo_flags = flags;
    sinfo.sinfo_stream = stream_no;
    sinfo.sinfo_timetolive = timetolive;
    sinfo.sinfo_context = context;
    sinfo.sinfo_assoc_id = 0;

    ua.sd = s;
    ua.m = __DECONST(struct mbuf *, m);
    ua.msg = NULL;
    ua.mlen = m->m_pkthdr.len;
    ua.to = __DECONST(caddr_t, to);
    ua.tolen = tolen;
    ua.sinfo = &sinfo;
    ua.flags = flags;
    
	rc = sys_sctp_generic_sendmsg(curthread, &ua);
    if (rc) {
        ff_os_errno(rc);
        return -1;
    }

    return curthread->td_retval[0];
}

#undef SCTP_CONTROL_VEC_SIZE_RCV

struct mbuf *
ff_datatombuf(caddr_t data, ssize_t length)
{
    struct mbuf *m;
    struct uio uio;
	struct iovec iov[1];

    iov[0].iov_base = data;
	iov[0].iov_len = length;

    uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_USERSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = NULL;
	uio.uio_offset = 0; 
    uio.uio_resid = length;

    m = m_uiotombuf(&uio, M_WAITOK, length, 0, 0);
    if (m == NULL) {
        printf("%s %d\n", __FUNCTION__, __LINE__);
    }

    m->m_pkthdr.len = length;
    
    return m;
}

struct mbuf *
ff_mbuf_dup(struct mbuf *m, int total)
{
    struct mbuf *n, *hdr;

    if (m == NULL)
        return NULL;

    hdr = m_gethdr(M_NOWAIT, m->m_type);
    if (hdr == NULL)
        return NULL;
#if 0
    n = m_getm2(NULL, max(total, 1), M_WAITOK, MT_DATA, 0);
	if (n == NULL)
		goto err_out;

    bcopy(m->m_data, n->m_data, m->m_len);
    n->m_len = m->m_len;
#else
    n = m_copym(m, 0, M_COPYALL, M_NOWAIT);
    if (n == NULL)
		goto err_out;
#endif

    hdr->m_len = 0;
    hdr->m_pkthdr.len = total;
    hdr->m_next = n;

    return hdr;
err_out:
    if (hdr != NULL)
        m_freem(hdr);

    return NULL;
}

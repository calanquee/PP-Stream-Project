/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string>
#include <sstream>

#include "tcp_address.hpp"
#include <stdint.h>
#include "err.hpp"
#include "ip.hpp"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>

//  Some platforms (notably Darwin/OSX and NetBSD) do not define all AI_
//  flags for getaddrinfo(). This can be worked around safely by defining
//  these to 0.
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif


#include <ifaddrs.h>

//  On these platforms, network interface name can be queried
//  using getifaddrs function.
int afs_zmq::tcp_address_t::resolve_nic_name (const char *nic_, bool ipv6_)
{
    //  Get the addresses.
    ifaddrs *ifa = NULL;
    int rc = getifaddrs (&ifa);
    errno_assert (rc == 0);
    zmq_assert (ifa != NULL);

    //  Find the corresponding network interface.
    bool found = false;
    for (ifaddrs *ifp = ifa; ifp != NULL ;ifp = ifp->ifa_next)
    {
        if (ifp->ifa_addr == NULL)
            continue;

        int family = ifp->ifa_addr->sa_family;
        if ((family == AF_INET || (ipv6_ && family == AF_INET6))
        && !strcmp (nic_, ifp->ifa_name)) {
            memcpy (&address, ifp->ifa_addr,
                    (family == AF_INET) ? sizeof (struct sockaddr_in)
                                        : sizeof (struct sockaddr_in6));
            found = true;
            break;
        }
    }

    //  Clean-up;
    freeifaddrs (ifa);

    if (!found) {
        errno = ENODEV;
        return -1;
    }
    return 0;
}

int afs_zmq::tcp_address_t::resolve_interface (const char *interface_, bool ipv6_)
{
    //  Initialize temporary output pointers with storage address.
    sockaddr_storage ss;
    sockaddr *out_addr = (sockaddr*) &ss;
    size_t out_addrlen;

    //  Initialise IP-format family/port and populate temporary output pointers
    //  with the address.
    if (ipv6_) {
        sockaddr_in6 ip6_addr;
        memset (&ip6_addr, 0, sizeof (ip6_addr));
        ip6_addr.sin6_family = AF_INET6;
        memcpy (&ip6_addr.sin6_addr, &in6addr_any, sizeof (in6addr_any));
        out_addrlen = sizeof ip6_addr;
        memcpy (out_addr, &ip6_addr, out_addrlen);
    }
    else {
        sockaddr_in ip4_addr;
        memset (&ip4_addr, 0, sizeof (ip4_addr));
        ip4_addr.sin_family = AF_INET;
        ip4_addr.sin_addr.s_addr = htonl (INADDR_ANY);
        out_addrlen = sizeof ip4_addr;
        memcpy (out_addr, &ip4_addr, out_addrlen);
    }
    //  "*" resolves to INADDR_ANY or in6addr_any.
    if (strcmp (interface_, "*") == 0) {
        zmq_assert (out_addrlen <= sizeof address);
        memcpy (&address, out_addr, out_addrlen);
        return 0;
    }

    //  Try to resolve the string as a NIC name.
    int rc = resolve_nic_name (interface_, ipv6_);
    if (rc != 0 && errno != ENODEV)
        return rc;
    if (rc == 0)
        return 0;

    //  There's no such interface name. Assume literal address.
    addrinfo *res = NULL;
    addrinfo req;
    memset (&req, 0, sizeof (req));

    //  Choose IPv4 or IPv6 protocol family. Note that IPv6 allows for
    //  IPv4-in-IPv6 addresses.
    req.ai_family = ipv6_? AF_INET6: AF_INET;

    //  Arbitrary, not used in the output, but avoids duplicate results.
    req.ai_socktype = SOCK_STREAM;

    //  Restrict hostname/service to literals to avoid any DNS lookups or
    //  service-name irregularity due to indeterminate socktype.
    req.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    //  Resolve the literal address. Some of the error info is lost in case
    //  of error, however, there's no way to report EAI errors via errno.
    rc = getaddrinfo (interface_, NULL, &req, &res);
    if (rc) {
        errno = ENODEV;
        return -1;
    }

    //  Use the first result.
    zmq_assert (res != NULL);
    zmq_assert ((size_t) (res->ai_addrlen) <= sizeof (address));
    memcpy (&address, res->ai_addr, res->ai_addrlen);

    //  Cleanup getaddrinfo after copying the possibly referenced result.
    freeaddrinfo (res);

    return 0;
}

int afs_zmq::tcp_address_t::resolve_hostname (const char *hostname_, bool ipv6_)
{
    //  Set up the query.
    addrinfo req;
    memset (&req, 0, sizeof (req));

    //  Choose IPv4 or IPv6 protocol family. Note that IPv6 allows for
    //  IPv4-in-IPv6 addresses.
    req.ai_family = ipv6_? AF_INET6: AF_INET;

    //  Need to choose one to avoid duplicate results from getaddrinfo() - this
    //  doesn't really matter, since it's not included in the addr-output.
    req.ai_socktype = SOCK_STREAM;

    //  Resolve host name. Some of the error info is lost in case of error,
    //  however, there's no way to report EAI errors via errno.
    addrinfo *res;
    int rc = getaddrinfo (hostname_, NULL, &req, &res);
    if (rc) {
        switch (rc) {
        case EAI_MEMORY:
            errno = ENOMEM;
            break;
        default:
            errno = EINVAL;
            break;
        }
        return -1;
    }

    //  Copy first result to output addr with hostname and service.
    zmq_assert ((size_t) (res->ai_addrlen) <= sizeof (address));
    memcpy (&address, res->ai_addr, res->ai_addrlen);

    freeaddrinfo (res);

    return 0;
}

afs_zmq::tcp_address_t::tcp_address_t ()
{
    memset (&address, 0, sizeof (address));
}

afs_zmq::tcp_address_t::tcp_address_t (const sockaddr *sa, socklen_t sa_len)
{
    zmq_assert(sa && sa_len > 0);

    memset (&address, 0, sizeof (address));
    if (sa->sa_family == AF_INET && sa_len >= (socklen_t) sizeof (address.ipv4))
        memcpy(&address.ipv4, sa, sizeof (address.ipv4));
    else 
    if (sa->sa_family == AF_INET6 && sa_len >= (socklen_t) sizeof (address.ipv6))
        memcpy(&address.ipv6, sa, sizeof (address.ipv6));
}

afs_zmq::tcp_address_t::~tcp_address_t ()
{
}

int afs_zmq::tcp_address_t::resolve (const char *name_, bool local_, bool ipv6_)
{
    //  Find the ':' at end that separates address from the port number.
    const char *delimiter = strrchr (name_, ':');
    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }
    //  Separate the address/port.
    std::string addr_str (name_, delimiter - name_);
    std::string port_str (delimiter + 1);

    //  Remove square brackets around the address, if any.
    if (addr_str.size () >= 2 && addr_str [0] == '[' &&
          addr_str [addr_str.size () - 1] == ']')
        addr_str = addr_str.substr (1, addr_str.size () - 2);

    //  Allow 0 specifically, to detect invalid port error in atoi if not
    uint16_t port;
    if (port_str == "*" || port_str == "0")
        //  Resolve wildcard to 0 to allow autoselection of port
        port = 0;
    else {
        //  Parse the port number (0 is not a valid port).
        port = (uint16_t) atoi (port_str.c_str ());
        if (port == 0) {
            errno = EINVAL;
            return -1;
        }
    }

    //  Resolve the IP address.
    int rc;
    if (local_)
        rc = resolve_interface (addr_str.c_str (), ipv6_);
    else
        rc = resolve_hostname (addr_str.c_str (), ipv6_);
    if (rc != 0)
        return -1;

    //  Set the port into the address structure.
    if (address.generic.sa_family == AF_INET6)
        address.ipv6.sin6_port = htons (port);
    else
        address.ipv4.sin_port = htons (port);

    return 0;
}

int afs_zmq::tcp_address_t::to_string (std::string &addr_)
{
    if (address.generic.sa_family != AF_INET
    &&  address.generic.sa_family != AF_INET6) {
        addr_.clear ();
        return -1;
    }

    // not using service resolv because of https://github.com/zeromq/libzmq/commit/1824574f9b5a8ce786853320e3ea09fe1f822bc4
    char hbuf[NI_MAXHOST];
    int rc = getnameinfo (addr (), addrlen (), hbuf, sizeof (hbuf), NULL, 0, NI_NUMERICHOST);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    if (address.generic.sa_family == AF_INET6) {
        std::stringstream s;
        s << "tcp://[" << hbuf << "]:" << ntohs (address.ipv6.sin6_port);
        addr_ = s.str ();
    }
    else {
        std::stringstream s;
        s << "tcp://" << hbuf << ":" << ntohs (address.ipv4.sin_port);
        addr_ = s.str ();
    };
    return 0;
}

const sockaddr *afs_zmq::tcp_address_t::addr () const
{
    return &address.generic;
}

socklen_t afs_zmq::tcp_address_t::addrlen () const
{
    if (address.generic.sa_family == AF_INET6)
        return (socklen_t) sizeof (address.ipv6);
    else
        return (socklen_t) sizeof (address.ipv4);
}

sa_family_t afs_zmq::tcp_address_t::family () const
{
    return address.generic.sa_family;
}

afs_zmq::tcp_address_mask_t::tcp_address_mask_t () :
    tcp_address_t ()
{
    address_mask = -1;
}

int afs_zmq::tcp_address_mask_t::mask () const
{
    return address_mask;
}

int afs_zmq::tcp_address_mask_t::resolve (const char *name_, bool ipv6_)
{
    // Find '/' at the end that separates address from the cidr mask number.
    // Allow empty mask clause and threat it like '/32' for ipv4 or '/128' for ipv6.
    std::string addr_str, mask_str;
    const char *delimiter = strrchr (name_, '/');
    if (delimiter != NULL) {
        addr_str.assign (name_, delimiter - name_);
        mask_str.assign (delimiter + 1);
        if (mask_str.empty ()) {
            errno = EINVAL;
            return -1;
        }
    }
    else
        addr_str.assign (name_);

    // Parse address part using standard routines.
    int rc = tcp_address_t::resolve_hostname (addr_str.c_str (), ipv6_);
    if (rc != 0)
        return rc;

    // Parse the cidr mask number.
    if (mask_str.empty ()) {
        if (address.generic.sa_family == AF_INET6)
            address_mask = 128;
        else
            address_mask = 32;
    }
    else
    if (mask_str == "0") {
        address_mask = 0;
    }
    else {
        int mask = atoi (mask_str.c_str ());
        if (
            (mask < 1) ||
            (address.generic.sa_family == AF_INET6 && mask > 128) ||
            (address.generic.sa_family != AF_INET6 && mask > 32)
        ) {
            errno = EINVAL;
            return -1;
        }
        address_mask = mask;
    }

    return 0;
}

int afs_zmq::tcp_address_mask_t::to_string (std::string &addr_)
{
    if (address.generic.sa_family != AF_INET && address.generic.sa_family != AF_INET6) {
        addr_.clear ();
        return -1;
    }
    if (address_mask == -1) {
        addr_.clear ();
        return -1;
    }

    char hbuf[NI_MAXHOST];
    int rc = getnameinfo (addr (), addrlen (), hbuf, sizeof (hbuf), NULL, 0, NI_NUMERICHOST);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    if (address.generic.sa_family == AF_INET6) {
        std::stringstream s;
        s << "[" << hbuf << "]/" << address_mask;
        addr_ = s.str ();
    }
    else {
        std::stringstream s;
        s << hbuf << "/" << address_mask;
        addr_ = s.str ();
    };
    return 0;
}

bool afs_zmq::tcp_address_mask_t::match_address (const struct sockaddr *ss, const socklen_t ss_len) const
{
    zmq_assert (address_mask != -1 && ss != NULL && ss_len >= (socklen_t) sizeof (struct sockaddr));

    if (ss->sa_family != address.generic.sa_family)
        return false;

    if (address_mask > 0) {
        int mask;
        const uint8_t *our_bytes, *their_bytes;
        if (ss->sa_family == AF_INET6) {
            zmq_assert (ss_len == sizeof (struct sockaddr_in6));
            their_bytes = (const uint8_t *) &(((const struct sockaddr_in6 *) ss)->sin6_addr);
            our_bytes = (const uint8_t *) &address.ipv6.sin6_addr;
            mask = sizeof (struct in6_addr) * 8;
        }
        else {
            zmq_assert (ss_len == sizeof (struct sockaddr_in));
            their_bytes = (const uint8_t *) &(((const struct sockaddr_in *) ss)->sin_addr);
            our_bytes = (const uint8_t *) &address.ipv4.sin_addr;
            mask = sizeof (struct in_addr) * 8;
        }
        if (address_mask < mask) mask = address_mask;

        size_t full_bytes = mask / 8;
        if (memcmp(our_bytes, their_bytes, full_bytes))
            return false;

        uint8_t last_byte_bits = (0xffU << (8 - (mask % 8))) & 0xffU;
        if (last_byte_bits) {
            if ((their_bytes[full_bytes] & last_byte_bits) != (our_bytes[full_bytes] & last_byte_bits))
                return false;
        }
    }

    return true;
}

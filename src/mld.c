/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "mld.h"
#include "log.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define MLD2_CAPABLE_ROUTERS "ff02::16" /* all MLDv2-capable routers */
#define MLD2_LISTEN_REPORT 143 /* Multicast Listener Report messages */
#define BUFSIZE 1500

#if !__USE_KERNEL_IPV6_DEFS
/* IPv6 packet information.  */
struct in6_pktinfo
{
	struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
	unsigned int ipi6_ifindex;  /* send/recv interface index */
};
#endif

/* Multicast Address Record */
struct mar {
	uint8_t         mar_type;       /* Record Type */
	uint8_t         mar_auxlen;     /* Aux Data Len */
	uint16_t        mar_sources;    /* Number of Sources */
	struct in6_addr mar_address;    /* Multicast Address */
} __attribute__((__packed__));

/* extract interface number from ancillary control data */
int interface_index(struct msghdr msg)
{
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	int ifidx = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_PKTINFO)
			continue;
		pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		ifidx = pi->ipi6_ifindex;
	}
	return ifidx;
}

int mld_wait(struct in6_addr *addr)
{
	int ret = 0;
	int opt = 1;
	int joins = 0;
	int sock;
	int ifidx;
	ssize_t byt;
	struct ipv6_mreq req;
	struct ifaddrs *ifaddr, *ifa;
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct mar mrec = {0};
	struct msghdr msg;
	char buf_ctrl[BUFSIZE];
	char buf_name[BUFSIZE];
	char straddr[INET6_ADDRSTRLEN];
	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	assert(sock);
	if (sock == -1) {
		perror("socket()");
		return -1;
	}
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));
	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family !=AF_INET6) continue; /* ipv6 only */
		inet_pton(AF_INET6, MLD2_CAPABLE_ROUTERS, &(req.ipv6mr_multiaddr));
		req.ipv6mr_interface = if_nametoindex(ifa->ifa_name);
		ret = setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req));
		if (ret != -1) {
			DEBUG("listening on interface %s", ifa->ifa_name);
			joins++;
		}
	}
	freeifaddrs(ifaddr);
	if (!joins) {
		ERROR("Unable to join on any interfaces");
		return -1;
	}
	iov[0].iov_base = &icmpv6;
	iov[0].iov_len = sizeof icmpv6;
	iov[1].iov_base = &mrec;
	iov[1].iov_len = sizeof mrec;
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = BUFSIZE;
	msg.msg_name = buf_name;
	msg.msg_namelen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_flags = 0;
	for (;;) {
		if ((byt = recvmsg(sock, &msg, 0)) == -1) {
			perror("recvmsg()");
			return -1;
		}
		ifidx = interface_index(msg);
		if (icmpv6.icmp6_type == MLD2_LISTEN_REPORT) {
			uint16_t rec = ntohs(icmpv6.icmp6_data16[1]);
			DEBUG("got a MLD2_LISTEN_REPORT with %u records", rec);
			for (int i = 0; i < rec; i++) {
				if (!memcmp(addr, &mrec.mar_address, sizeof(struct in6_addr))) {
					inet_ntop(AF_INET6, (&mrec.mar_address)->s6_addr, straddr, INET6_ADDRSTRLEN);
					DEBUG("MATCH FOUND: %s", straddr);
					return 0;
				}
			}
		}
	}
	close(sock);
	return 0;
}

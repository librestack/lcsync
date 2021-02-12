/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "mld_pvt.h"
#include "hash.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <poll.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile int cont = 1;

/* extract interface number from ancillary control data */
static unsigned int interface_index(struct msghdr *msg)
{
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pi;
	unsigned int ifidx = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6 || cmsg->cmsg_type != IPV6_PKTINFO)
			continue;
		pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		ifidx = pi->ipi6_ifindex;
	}
	return ifidx;
}

static unsigned int mld_idx_iface(mld_t *mld, unsigned int idx)
{
	DEBUG("%s() mld->len = %i", __func__, mld->len);
	DEBUG("%s() looking for %u", __func__, idx);
	for (int i = 0; i < mld->len; i++) {
		DEBUG("mld->ifx[i]=%u", mld->ifx[i]);
		if (mld->ifx[i] == idx) return i;
	}
	return 0;
}

void mld_free(mld_t *mld)
{
	job_queue_destroy(mld->timerq);
	lc_ctx_free(mld->lctx);
	free(mld);
}

void mld_stop(mld_t *mld)
{
	if(!mld) return;
	if (mld->sock) {
		struct ipv6_mreq req;
		setsockopt(mld->sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &req, sizeof(req));
		close(mld->sock);
	}
	mld_free(mld);
}

void vec_dump(vec_t *vec, int idx)
{
	for (int j = 0; j < 16; j++) {
		fprintf(stderr, "%u ", (uint8_t)vec[idx / VECTOR_BITS].u8[j]);
	}
	putc('\n', stderr);
}

/* decrement all the counters. There are 16.7 million of them, use SIMD */
void mld_timer_tick(mld_t *mld, unsigned int iface, size_t idx)
{
	(void)iface; (void)idx;
	vec_t *t;
	vec_t mask = {0};
	for (int i = 0; i < mld->len; i++) {
		t = mld->filter[i].t;
		for (size_t z = 0; z < BLOOM_VECTORS; z++) {
			mask.u8 = t[z].u8 > 0;
			t[z].u8 += mask.u8;
			if (*(mld->cont) == 0) return;
		}
	}
	DEBUG("%s() - update complete", __func__);
}

void mld_timer_refresh(mld_t *mld, unsigned int iface, size_t idx)
{
	vec_t *t = mld->filter[iface].t;
	vec_set_epi8(t, idx, MLD_TIMEOUT);
	DEBUG("timer refreshed (%zu)", idx);
}

void *mld_timer_job(void *arg)
{
	mld_timerjob_t *tj = (mld_timerjob_t *)arg;
	tj->f(tj->mld, tj->iface, tj->idx);
	return arg;
}

/* this thread handles the clock ticks, creating a job for the timer thread */
void mld_timer_ticker(mld_t *mld, unsigned int iface, size_t idx)
{
	struct timespec ts;
	sem_t sem;
	mld_timerjob_t tj = { .mld = mld, .iface = iface, .idx = idx, .f = &mld_timer_tick };
	sem_init(&sem, 0, 0);
	clock_gettime(CLOCK_REALTIME, &ts);
	for (;;) {
		ts.tv_sec += MLD_TIMER_INTERVAL;
		sem_timedwait(&sem, &ts);
		job_push_new(mld->timerq, &mld_timer_job, &tj, sizeof tj, &free, JOB_COPY|JOB_FREE);
	}
}

/* create side channel by hashing event type with main channel addr */
/* FIXME this belongs in the main librecast net API */
lc_channel_t * lc_channel_sidehash(lc_ctx_t *lctx, struct in6_addr *addr, int band)
{
	char base[INET6_ADDRSTRLEN] = "";
	char hash[INET6_ADDRSTRLEN] = "";
	int rc;
	if (!inet_ntop(AF_INET6, addr, base, INET6_ADDRSTRLEN)) {
		ERROR("inet_ntop()");
		return NULL;
	}
	if ((rc = lc_hashgroup(base, (unsigned char *)&band, sizeof band, hash, 0))) {
		ERROR("ERROR: lc_hashgroup = %i", rc);
		return NULL;
	}
	DEBUG("%s() channel group address: %s", __func__, hash);
	return lc_channel_init(lctx, hash, MLD_EVENT_SERV);
}
#if 0
lc_channel_t * lc_channel_sideband(lc_ctx_t *lctx, struct in6_addr *addr, int band)
{
	/* create side band by XORing byte of address corresponding to band */
#if 0
	band &= 0xe;
	(char)addr[band] ^= (char)addr[band];
	return lc_channel_init(lctx, addr, MLD_EVENT_SERV);
#endif
	return NULL;
}
#endif

/* wait on a specific address */
int mld_wait(mld_t *mld, unsigned int iface, struct in6_addr *addr)
{
	struct pollfd fds = { .events = POLL_IN };
	int rc = 0;
	DEBUG("%s() mld has address %p", __func__, (void*)mld);
	if (mld_filter_grp_cmp(mld, iface, addr)) {
		DEBUG("%s() - no need to wait - filter has address", __func__);
		return 0;
	}
	lc_socket_t *sock = lc_socket_new(mld->lctx);
	lc_channel_t *chan = lc_channel_sidehash(mld->lctx, addr, MLD_EVENT_ALL);
	mld_filter_grp_add_ai(mld, iface, lc_channel_addrinfo(chan)); /* avoid race */
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	fds.fd = lc_socket_raw(sock);
	while (!(rc = poll(&fds, 1, 100)) && (*(mld->cont)));
	if (rc > 0) DEBUG("%s() notify received", __func__);
	lc_channel_part(chan);
	lc_channel_free(chan);
	lc_socket_close(sock);
	return 0;
}

void mld_notify(mld_t *mld, struct in6_addr *saddr, int event)
{
	lc_message_t msg = {0};
	lc_socket_t *sock;
	lc_channel_t *chan[MLD_EVENT_MAX];
	struct addrinfo *ai;
	char straddr1[INET6_ADDRSTRLEN];
	char straddr2[INET6_ADDRSTRLEN];
	const int opt = 1;

	// TODO notify event specific side channels
	(void) event;
	chan[0] = lc_channel_sidehash(mld->lctx, saddr, MLD_EVENT_ALL);

	/* check filter to see if anyone listening for notifications */
	ai = lc_channel_addrinfo(chan[0]);
	inet_ntop(AF_INET6, saddr, straddr1, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, aitoin6(ai), straddr2, INET6_ADDRSTRLEN);
	if (!mld_filter_grp_cmp(mld, 0, aitoin6(ai))) {
		DEBUG("no one listening to %s - skipping notification for %s", straddr2, straddr1);
		return;
	}
	DEBUG("sending notification for event on %s to %s", straddr1, straddr2);

	sock = lc_socket_new(mld->lctx);
	/* set loopback so machine-local listeners are notified */
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	/* set TTL to 1 so notification doesn't leave local segment */
	lc_socket_setopt(sock, IPV6_MULTICAST_HOPS, &opt, sizeof(opt));
	lc_channel_bind(sock, chan[0]);
	lc_msg_send(chan[0], &msg);
}

int mld_filter_grp_del_f(mld_t *mld, unsigned int iface, size_t idx, vec_t *v)
{
	(void)mld; (void)iface;
	if (vec_get_epi8(v, idx)) vec_dec_epi8(v, idx);
	return 0;
}

int mld_filter_grp_add_f(mld_t *mld, unsigned int iface, size_t idx, vec_t *v)
{
	mld_timerjob_t tj = { .mld = mld, .iface = iface, .f = &mld_timer_refresh };
	if (vec_get_epi8(v, idx) != CHAR_MAX) vec_inc_epi8(v, idx);
	tj.idx = idx;
	job_push_new(mld->timerq, &mld_timer_job, &tj, sizeof tj, &free, JOB_COPY|JOB_FREE);
	return 0;
}

int mld_filter_timer_get_f(mld_t *mld, unsigned int iface, size_t idx, vec_t *v)
{
	(void)mld; (void)iface;
	return vec_get_epi8(v, idx);
}

int mld_filter_grp_cmp_f(mld_t *mld, unsigned int iface, size_t idx, vec_t *v)
{
	(void)mld; (void)iface;
	return !vec_get_epi8(v, idx);
}

int mld_filter_grp_call(mld_t *mld, unsigned int iface, struct in6_addr *saddr, vec_t *v,
		int(*f)(mld_t *, unsigned int, size_t, vec_t *))
{
	size_t idx;
	uint32_t hash[BLOOM_HASHES];
	int rc = 0, notify = 0;
	if (iface >= (unsigned)mld->len) {
		errno = EINVAL;
		return -1;
	}
	if (f != &mld_filter_grp_cmp_f && f != mld_filter_timer_get_f) {
		/* add requires the entry NOT to exist, del requires that it does */
		int required = !(f == &mld_filter_grp_del_f);
		if (mld_filter_grp_cmp(mld, iface, saddr) == required) return 0;
		if (f == mld_filter_grp_add_f) notify = MLD_EVENT_JOIN;
		if (f == mld_filter_grp_del_f) notify = MLD_EVENT_PART;
	}
	hash_generic((unsigned char *)hash, sizeof hash, saddr->s6_addr, IPV6_BYTES);
	for (int i = 0; i < BLOOM_HASHES; i++) {
		idx = hash[i] % BLOOM_SZ;
		if ((rc = f(mld, iface, idx, v))) break; /* error or found */
		if (f == &mld_filter_timer_get_f) break; /* use first result for timer */
	}
	if (!rc && notify) mld_notify(mld, saddr, notify);
	return rc;
}

int mld_filter_timer_get(mld_t *mld, unsigned int iface, struct in6_addr *saddr)
{
	vec_t *t = mld->filter[iface].t;
	return mld_filter_grp_call(mld, iface, saddr, t, &mld_filter_timer_get_f);
}

int mld_filter_grp_cmp(mld_t *mld, unsigned int iface, struct in6_addr *saddr)
{
	vec_t *grp = mld->filter[iface].grp;
	return !mld_filter_grp_call(mld, iface, saddr, grp, &mld_filter_grp_cmp_f);
}

int mld_filter_grp_del(mld_t *mld, unsigned int iface, struct in6_addr *saddr)
{
#ifdef MLD_DEBUG
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, saddr, straddr, INET6_ADDRSTRLEN);
	DEBUG("%s(): %s", __func__, straddr);
#endif
	vec_t *grp = mld->filter[iface].grp;
	return mld_filter_grp_call(mld, iface, saddr, grp, &mld_filter_grp_del_f);
}

int mld_filter_grp_del_ai(mld_t *mld, unsigned int iface, struct addrinfo *ai)
{
	return mld_filter_grp_del(mld, iface, aitoin6(ai));
}

int mld_filter_grp_add(mld_t *mld, unsigned int iface, struct in6_addr *saddr)
{
#ifdef MLD_DEBUG
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, saddr, straddr, INET6_ADDRSTRLEN);
	DEBUG("%s(): %s", __func__, straddr);
#endif
	vec_t *grp = mld->filter[iface].grp;
	return mld_filter_grp_call(mld, iface, saddr, grp, &mld_filter_grp_add_f);
}

int mld_filter_grp_add_ai(mld_t *mld, unsigned int iface, struct addrinfo *ai)
{
	return mld_filter_grp_add(mld, iface, aitoin6(ai));
}

int mld_thatsme(struct in6_addr *addr)
{
	int ret = 1;
	struct ifaddrs *ifaddr, *ifa;
	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) continue;
		if (ifa->ifa_addr->sa_family != AF_INET6) continue;
		if (!memcmp(ifa->ifa_addr, addr, sizeof (struct in6_addr))) {
			ret = 0; break;
		}
	}
	freeifaddrs(ifaddr);
	return ret;
}

void mld_address_record(mld_t *mld, unsigned int iface, mld_addr_rec_t *rec)
{
	struct in6_addr grp = rec->addr;
	struct in6_addr *src = rec->src;
	int idx = -1;
	switch (rec->type) {
		case MODE_IS_INCLUDE:
		case CHANGE_TO_INCLUDE_MODE:
			if (!rec->srcs) {
				mld_filter_grp_del(mld, iface, &grp);
				break;
			}
			for (int i = 0; i < rec->srcs; i++) {
				if (!mld_thatsme(&src[i])) {
					idx = i;
					break;
				}
			}
			if (idx < 0) break;
			/* fallthru */
		case MODE_IS_EXCLUDE:
		case CHANGE_TO_EXCLUDE_MODE:
			mld_filter_grp_add(mld, iface, &grp);
			break;
	}
}

void mld_listen_report(mld_t *mld, struct msghdr *msg)
{
	struct icmp6_hdr *icmpv6 = msg->msg_iov[0].iov_base;
	mld_addr_rec_t *mrec = msg->msg_iov[1].iov_base;
	unsigned int iface = mld_idx_iface(mld, interface_index(msg));
	uint16_t recs = ntohs(icmpv6->icmp6_data16[1]);
	for (int i = 0; i < recs; i++) {
		mld_address_record(mld, iface, &mrec[i]);
	}
}

void mld_msg_handle(mld_t *mld, struct msghdr *msg)
{
	struct icmp6_hdr *icmpv6 = msg->msg_iov[0].iov_base;
	if (icmpv6->icmp6_type == MLD2_LISTEN_REPORT) {
		mld_listen_report(mld, msg);
	}
}

int mld_listen(mld_t *mld)
{
	mld_addr_rec_t mrec = {0};
	struct iovec iov[2] = {0};
	struct icmp6_hdr icmpv6 = {0};
	struct msghdr msg = {0};
	struct pollfd fds = { .fd = mld->sock, .events = POLL_IN };
	char buf_ctrl[BUFSIZE];
	char buf_name[IPV6_BYTES];
	int rc = 0;
	assert(mld);
	if (!mld->sock) {
		errno = ENOTSOCK;
		return -1;
	}
	iov[0].iov_base = &icmpv6;
	iov[0].iov_len = sizeof icmpv6;
	iov[1].iov_base = &mrec;
	iov[1].iov_len = sizeof mrec;
	msg.msg_name = buf_name;
	msg.msg_namelen = IPV6_BYTES;
	msg.msg_control = buf_ctrl;
	msg.msg_controllen = BUFSIZE;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_flags = 0;
	DEBUG("MLD listener ready");
	assert(mld->cont);
	while (*(mld->cont)) {
		while (!(rc = poll(&fds, 1, 100)) && *(mld->cont));
		if (rc == -1) {
			perror("poll()");
			return -1;
		}
		if (*(mld->cont)) {
			if ((recvmsg(mld->sock, &msg, 0)) == -1) {
				perror("recvmsg()");
				return -1;
			}
			DEBUG("%s(): msg received", __func__);
			mld_msg_handle(mld, &msg);
		}
	}
	return 0;
}

void *mld_listen_job(void *arg)
{
	assert(arg);
	mld_t *mld = *(mld_t **)arg;
	mld_listen(mld);
	return arg;
}

mld_t *mld_init(int ifaces)
{
	mld_t *mld = calloc(1, sizeof(mld_t) + ifaces * sizeof(mld_filter_t));
	if (!mld) return NULL;
	mld->len = ifaces;
	mld->cont = &cont;
	/* create FIFO queue with timer writer thread + ticker + MLD listener */
	mld->timerq = job_queue_create(3);
	if (!(mld->lctx = lc_ctx_new())) {
		ERROR("Failed to create librecast context");
		free(mld);
		mld = NULL;
	}
	return mld;
}

mld_t *mld_start(volatile int *cont)
{
	mld_t *mld = NULL;
	struct ifaddrs *ifaddr = {0};
	struct ipv6_mreq req = {0};
	const int opt = 1;
	unsigned int ifx[IFACE_MAX] = {0};
	int joins = 0;
	int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock == -1) {
		perror("socket()");
		return NULL;
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt))) {
		perror("setsockopt()");
		goto exit_err_0;
	}
	if (getifaddrs(&ifaddr)) {
		perror("getifaddrs()");
		goto exit_err_0;
	}
	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family !=AF_INET6) continue; /* ipv6 only */
		if (inet_pton(AF_INET6, MLD2_CAPABLE_ROUTERS, &(req.ipv6mr_multiaddr)) != 1)
			continue;
		if (!(req.ipv6mr_interface = if_nametoindex(ifa->ifa_name))) continue;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req)) != -1) {
			unsigned int idx = if_nametoindex(ifa->ifa_name);
			DEBUG("listening on interface %s (%u)", ifa->ifa_name, idx);
			if (!idx) perror("if_nametoindex()"); assert(idx);
			ifx[joins++] = idx;
		}
	}
	freeifaddrs(ifaddr);
	if (!joins) {
		ERROR("Unable to join on any interfaces");
		return NULL;
	}
	DEBUG("%s() listening on %i interfaces", __func__, joins);
	mld = mld_init(joins);
	if (!mld) goto exit_err_0;
	if (cont) mld->cont = cont;
	memcpy(mld->ifx, ifx, sizeof ifx);
	mld->sock = sock;
	mld_timerjob_t tj = { .mld = mld, .f = &mld_timer_ticker };
	job_push_new(mld->timerq, &mld_timer_job, &tj, sizeof tj, &free, JOB_COPY|JOB_FREE);
	job_push_new(mld->timerq, &mld_listen_job, &mld, sizeof mld, &free, JOB_COPY|JOB_FREE);
	return mld;
exit_err_0:
	close(sock);
	return NULL;
}

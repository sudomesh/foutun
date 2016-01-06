/* 
 * FOU Tunnel Server
 *
 * This program waits for client messages and opens foo-over-udp tunnels.
 * The tunnelling protocol is GRE, encapsulated (via FOU) in UDP.
 *
 * Author: Alex Papazoglou <alex@sudomesh.org>
 */

#include "foutun.h"
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <time.h>

static char buf[1024];
static unsigned int tunid = 1;
static __u32 laddr;
static __u16 lport = FOU_DATA_PORT;
static struct timespec check_ts;
int server_exit_flag = 0;
uint32_t next_key = 0x0a0b0c0d;

#define CHECK_INTERVAL                 20
#define TUNNEL_COUNTDOWN               1
#define WAIT_SECS                      10

struct tunnel_info {
	char ifname[IFNAMSIZ];
	struct sockaddr_in dest;
	int countdown;
	int sockfd;
	uint32_t key;
	struct tunnel_info *next;
};

static struct tunnel_info *tinfo_head = NULL;

int open_control_socket()
{
	int sd;
	struct sockaddr_in sa;
	int r;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd<0)
		die("unable to open server socket\n");

	sa.sin_family = AF_INET;
	sa.sin_port = htons(FOU_CTRL_PORT);
	sa.sin_addr.s_addr = INADDR_ANY;

	r = bind(sd, (struct sockaddr *)&sa, sizeof(sa));
	if (r<0)
		die("unable to bind to server port\n");

	return sd;
}

int open_keepalive_socket(const char *ifname, __u32 laddr)
{
	int fd, r;
	struct sockaddr_in sa;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = laddr;
	sa.sin_port = htons(FOU_KEEPALIVE_PORT);

	r = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r < 0)
		goto close_out;

	r = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
	if (r < 0)
		goto close_out;

	return fd;

close_out:
	close(fd);
	return -1;
}

/* 
 * Go through the linked list and reply to any endpoints that
 * have pinged us.
 */
int do_keepalive_replies(fd_set *fds)
{
	struct msg m;
	struct sockaddr_in sa;
	socklen_t slen = sizeof(sa);
	struct tunnel_info *t;
	char buf[256];	
	int len;

	for (t=tinfo_head;t;t=t->next) {
		if (FD_ISSET(t->sockfd, fds)) {
			len = recvfrom(t->sockfd, buf, 256, 0, (struct sockaddr *)&sa, &slen);
			if (len < 0)
				return -1;

			parse_message(buf, len, &m);
			m.un.keepalive.token++;
			len = compose_message(buf, 256, &m);

			/* TODO: validate remote */

			sendto(t->sockfd, buf, len, 0, (struct sockaddr *)&sa, slen);
			t->countdown = TUNNEL_COUNTDOWN;
		}
	}

	return 0;
}

/* 
 * Add the tunnel socket fds to an fd_set
 */
void add_keepalive_sockets(fd_set *fds, int *maxfd)
{
	struct tunnel_info *t;

	for (t=tinfo_head;t;t=t->next) {
		if (t->sockfd > 0) {
			FD_SET(t->sockfd, fds);
			if (t->sockfd > *maxfd)
				*maxfd = t->sockfd;
		}
	}
}

/* 
 * Keep a a linked list of tunnels so we can clean them up when
 * we exit, or when they die off.
 */
int register_tunnel(const char *tunnel_name, struct sockaddr_in *sa, uint32_t tunnel_key)
{
	struct tunnel_info *t, **s;
	int cmp;

	t = malloc(sizeof(struct tunnel_info));
	if (!t)
		return -1;

	strncpy(t->ifname, tunnel_name, IFNAMSIZ);

	t->countdown = TUNNEL_COUNTDOWN;
	memcpy(&t->dest, sa, sizeof(*sa));

	t->key = tunnel_key;

	/* set up keepalive socket */
	t->sockfd = open_keepalive_socket(tunnel_name, laddr);

	/* lex order to detect duplicates */
	for (s=&tinfo_head;*s;s=&((*s)->next))
		if ((cmp = strcmp(tunnel_name, (*s)->ifname)) >= 0)
			break;

	if (!cmp)
		return -1;

	t->next = *s;
	*s = t;
	return 0;
}

void unregister_tunnel(const char *tunnel_name)
{
	struct tunnel_info **t;

	for (t=&tinfo_head;*t;t=&((*t)->next)) {
		struct tunnel_info *s = *t;
		if (strcmp(s->ifname, tunnel_name) == 0) {			
			*t = s->next;
			if (s->sockfd > 0)
				close(s->sockfd);
			free(s);
			break;
		}
	}
}

/* 
 * Check each tunnel for received packets, and delete those which
 * are inactive.
 */
void check_tunnels()
{
	struct tunnel_info *t;

	for (t=tinfo_head;t;t=t->next) {
		if (t->countdown) {
			t->countdown--;
			continue;
		} else {
			/* clean up dead tunnel */
			if_tunnel_del(t->ifname);
			fprintf(stderr, "cleaned up dead tunnel '%s'\n", t->ifname);
			unregister_tunnel(t->ifname);
		}
	}
}

/* 
 * Delete all tunnels.
 */
void cleanup_tunnels()
{
	struct tunnel_info *t = tinfo_head;

	trace("begin cleanup");
	while (t) {
		struct tunnel_info *s = t->next;
		if_tunnel_del(t->ifname);
		unregister_tunnel(t->ifname);
		t = s;
	}
	trace("all done");
}

/* 
 * Read the request from a new client
 */
int get_request(int sd, struct msg *m, struct sockaddr *sa, socklen_t *sl)
{
	int len, r;

	len = recvfrom(sd, buf, sizeof(buf), 0, sa, sl);
	if (len<0)
		die("recvfrom: %s\n", strerror(errno));

	r = parse_message(buf, len, m);

	if (r<0 || m->type != MSG_REQUEST)
		return 0;
	return 1;
}

int wait_for_packet(int sd, struct msg *m)
{
	fd_set fds;
	int r;
	struct timeval tv;
	int maxfd;

	FD_ZERO(&fds);
	FD_SET(sd, &fds);

	tv.tv_sec = WAIT_SECS;
	tv.tv_usec = 0;

	maxfd = sd;
	add_keepalive_sockets(&fds, &maxfd);

	r = select(maxfd+1, &fds, 0, 0, &tv);

	/* we could have caught a SIGINT */
	if (r < 0) {
		if (server_exit_flag)
			return 0;
		else
			die("select\n");
	}

	do_keepalive_replies(&fds);

	if (FD_ISSET(sd, &fds))
		return 1;
	
	return 0;	
}


int send_ack(int sd, struct sockaddr *sa, socklen_t sl, uint32_t tunnel_key)
{
	struct msg m;
	int len;
	char buf[256];

	m.type = MSG_REPLY;
	m.un.reply.peeraddr = laddr;
	m.un.reply.peerport = lport;
	m.un.reply.tunnelkey = tunnel_key;
	len = compose_message(buf, 256, &m);
	sendto(sd, buf, len, 0, sa, sl);

	return 0;
}


#if 0
/*
 * Find a free port. Return is big-endian.
 */
static unsigned short grab_udp_port()
{
	struct sockaddr_in sa;
	int fd, r;
	socklen_t sl = sizeof(sa);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd<0)
		return 0;

	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = 0;
	sa.sin_family = AF_INET;

	r = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r < 0)
		return 0;

	r = getsockname(fd, (struct sockaddr *)&sa, &sl);
	if (r < 0)
		return 0;

	close(fd);

	return sa.sin_port;
}

#endif

/* 
 * Create a tunnel, assign it an address and bring it up.
 */
static int open_tunnel(const char *tunnel_name, __u32 peeraddr, struct sockaddr_in *sa, uint32_t tunnel_key)
{
	int ifindex;
	char paddr[40];

	struct foutun f = {
		.saddr = 0,
		.sport = htons(lport),
		.daddr = sa->sin_addr.s_addr,
		.dport = sa->sin_port,
		.ttl = 64,
		.tos = 0
	};

	memcpy(f.ikey, &tunnel_key, 4);
	memcpy(f.okey, &tunnel_key, 4);

	inet_ntop(AF_INET, &sa->sin_addr.s_addr, paddr, 40);
	fprintf (stderr, "received message from %s:%d\n", paddr, ntohs(sa->sin_port));
	if_tunnel_new(tunnel_name, &f);

	ifindex = if_nametoindex(tunnel_name);

	if (if_addr_add(ifindex, laddr, peeraddr) < 0 ||
	    if_tunnel_up(tunnel_name) < 0 ||
	    if_tunnel_get(tunnel_name, &f) < 0) {
		fprintf (stderr, "failed to open tunnel for %s\n", paddr);
		return -1;
	}
	fprintf (stderr, "tunnel up for %s\n", paddr);

	return 0;
}

static void interrupt_handler(int sig)
{
	trace("caught SIGINT");
	server_exit_flag = 1;
}

int main(int argc, char **argv)
{
	int sd;
	struct sockaddr_in sa;
	socklen_t sl;
	struct msg m;
	struct sigaction sact;

	if (argc < 2)
		die("requires local peer address for tunnel\n");

	inet_pton(AF_INET, argv[1], &laddr);

	if (genl_resolve("fou", NULL) < 0)
		die("unable to resolve fou. is the 'fou' module loaded?\n");

	sd = open_control_socket();
	if (sd < 0)
		die("open_control_socket: %\n", strerror(errno));

	fou_port_del(lport);	
	if (fou_port_add(htons(lport)) < 0)
		die("unable to attach fou port\n");

	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = interrupt_handler;
	sigaction(SIGINT, &sact, NULL);	

	clock_gettime(CLOCK_MONOTONIC, &check_ts);
	while (1) {
		struct timespec ts;
		int r;

		sl = sizeof(sa);
		trace("tick");

		if (wait_for_packet(sd, &m) &&
		    get_request(sd, &m, (struct sockaddr *)&sa, &sl)) {
			if (m.type == MSG_REQUEST && m.un.request.peeraddr) {
				char tunnel_name[IFNAMSIZ];

				snprintf(tunnel_name, IFNAMSIZ, "foutun%d", tunid++);
				r = open_tunnel(tunnel_name, m.un.request.peeraddr, &sa, next_key);
				if (r == 0) {
					send_ack(sd, (struct sockaddr *)&sa, sizeof(sa), next_key);
					register_tunnel(tunnel_name, &sa, next_key);
					next_key++;
				} else {
					fprintf(stderr, "unable to open tunnel: %s\n", strerror(-r));
				}
			} else {
				fprintf (stderr, "received bogus message of type %d\n", m.type);	
			}			
		}

		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ts.tv_sec > check_ts.tv_sec + CHECK_INTERVAL) {
			memcpy(&check_ts, &ts, sizeof(ts));
			check_tunnels();
		}

		if (server_exit_flag) {
			cleanup_tunnels();
			break;
		}
	}

	fou_port_del(htons(lport));

	return 0;
}

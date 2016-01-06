/* 
 * FOU Tunnel Client
 *
 * This program transmits a request to a fou tunnel server and
 * then opens a tunnel after receiving a reply. It also sends
 * and receives keepalives for NAT traversal.
 *
 * Author: Alex Papazoglou <alex@sudomesh.org>
 */
#include <time.h>
#include <limits.h>
#include "foutun.h"

#define BUFSIZE         256

#define WAIT_SECS                   2
#define KEEPALIVE_TIMEOUT           5
#define KEEPALIVE_COUNTDOWN_MAX     5

static char buf[256];

static struct sockaddr_in dest;
static __u16 fou_lport, fou_rport;
static __u32 laddr, raddr;
static __u32 tunnelkey;
static char tunnel_name[IFNAMSIZ] = "fou";
static int keepalive_countdown = KEEPALIVE_COUNTDOWN_MAX;
static int keepalive_countdown_max = KEEPALIVE_COUNTDOWN_MAX;
static int keepalive_timeout = KEEPALIVE_TIMEOUT;
static int wait_secs = WAIT_SECS;
static int time_to_live = 255;
static char *executable;

int exit_flag = 0;

int init_socket()
{
	int sd;
	struct sockaddr_in sa;
	int r;
	socklen_t sl;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		die("socket\n");

	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = 0;
	sa.sin_family = AF_INET;

	r = bind(sd, (struct sockaddr *)&sa, sizeof(sa));
	if (r < 0)
		die("bind\n");

	sl = sizeof(sa);
	r = getsockname(sd, (struct sockaddr *)&sa, &sl);
	if (r < 0)
		die("getsockname");

	fou_lport = sa.sin_port;
	printf ("bound to port %d\n", ntohs(fou_lport));

	return sd;
}

int send_request(int sd)
{
	struct msg m;
	int msglen;
	int r;

	m.type = MSG_REQUEST;
	m.un.request.peeraddr = laddr;
	msglen = compose_message(buf, BUFSIZE, &m);

	r = sendto(sd, buf, msglen, 0, (struct sockaddr *)&dest, sizeof(dest));
	if (r < 0)
		die("sendto: %s\n", strerror(errno));

	return r;
}

int recv_ack(int sd)
{
	char buf[256];
	struct msg msg;
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int r;
	
	trace("in");
	r = recvfrom(sd, buf, 256, 0, (struct sockaddr *)&sa, &sl);
	if (r < 0)
		die("recvfrom\n");

	if (sa.sin_port != dest.sin_port || sa.sin_addr.s_addr != dest.sin_addr.s_addr)
		return 0;

	parse_message(buf, r, &msg);
	if (msg.type != MSG_REPLY)
		return 0;

	raddr = msg.un.reply.peeraddr;
	fou_rport = msg.un.reply.peerport;
	tunnelkey = msg.un.reply.tunnelkey;

	trace("out");
	return 1;
}

int wait_for_ack(int sd)
{
	fd_set fds;
	int r;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(sd, &fds);

	tv.tv_sec = wait_secs;
	tv.tv_usec = 0;

	r = select(sd+1, &fds, 0, 0, &tv);
	if (r < 0)
		die("select\n");

	if (FD_ISSET(sd, &fds) && recv_ack(sd))
		return 1;

	return 0;	
}

int set_up_tunnel()
{
	int r;
	struct foutun f = {
		.saddr = 0,
		.sport = fou_lport,
		.daddr = dest.sin_addr.s_addr,
		.dport = htons(fou_rport),
		.ttl = time_to_live,
		.tos = 0,
		.ifindex = 0,
		.pmtudisc = 1,
	};

	memcpy(&f.ikey, &tunnelkey, 4);
	memcpy(&f.okey, &tunnelkey, 4);

	fou_port_del(fou_lport);
	r = fou_port_add(fou_lport);
	if (r<0) 
		die("error adding rx port\n");

	r = if_tunnel_new(tunnel_name, &f);
	if (r<0)
		die("error creating tunnel\n");

	r = if_addr_add(if_nametoindex(tunnel_name), laddr, raddr);
	if (r < 0)
		die("error adding addresses to tunnel\n");

	r = if_tunnel_up(tunnel_name);
	if (r < 0)
		die("error bringing tunnel up\n");

	return 0;
}

int clean_up_tunnel()
{
	if_tunnel_del(tunnel_name);
	fou_port_del(fou_lport);
	return 0;
}

static void interrupt_handler(int sig)
{
	printf ("caught interrupt\n");
	exit_flag = 1;
}

int set_signal_handler()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = interrupt_handler;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	return 0;
}

int send_keepalive(int sd, struct sockaddr_in *sa, struct msg *m)
{
	char buf[256];
	int len;

	m->un.keepalive.token++;
	len = compose_message(buf, 256, m);
	trace("ping");
	return sendto(sd, buf, len, 0, (struct sockaddr *)sa, sizeof(*sa));
}

int recv_keepalive(int sd, struct sockaddr_in *sa, struct msg *m)
{
	char *buf[256];
	int len;
	socklen_t sl = sizeof(*sa);

	len = recvfrom(sd, buf, 256, 0, (struct sockaddr *)sa, &sl);
	if (len < 0)
		return -1;

	parse_message(buf, len, m);
	trace("pong");
	return 0;
}

/* 
 * This is the main loop after the tunnel is brought up.
 */
void keepalive()
{
	int sd, r;
	struct timeval tv;
	struct timespec ts[2];
	int ts_idx = 0;
	struct sockaddr_in sa;
	struct msg m;
	fd_set fds;	

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		die("unable to open keepalive socket\n");

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = laddr;
	sa.sin_port = 0;

	r = bind(sd, (struct sockaddr *)&sa, sizeof(sa));
	if (r < 0)
		die("unable to bind to keepalive socket: %s\n", strerror(errno));

	r = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, tunnel_name, strlen(tunnel_name));
	if (r < 0)
		die("unable to bind to interface '%s'\n", tunnel_name);

	m.type = MSG_KEEPALIVE;
	m.un.keepalive.token = 1;
	
	/* destination */
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = raddr;
	sa.sin_port = htons(FOU_KEEPALIVE_PORT);

	memset(&ts[0], 0, sizeof(struct timespec));
	ts_idx = 1;

	while (!exit_flag) {
		clock_gettime(CLOCK_MONOTONIC, &ts[ts_idx]);

		if (ts[ts_idx].tv_sec > ts[1-ts_idx].tv_sec + keepalive_timeout) {
			trace("keepalive");
			send_keepalive(sd, &sa, &m);
			keepalive_countdown--;
			if (keepalive_countdown <= 0) {
				trace("tunnel is dead, shutting down\n");
				return;
			}
			ts_idx = 1-ts_idx;
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_SET(sd, &fds);

		r = select(sd+1, &fds, NULL, NULL, &tv);

		if (exit_flag)
			break;

		if (r<0)
			die("select\n");

		if (FD_ISSET(sd, &fds)) {
			recv_keepalive(sd, &sa, &m);
			keepalive_countdown = keepalive_countdown_max;
		}
	}

}

static int lookup_dest(const char *addrp, const char *port)
{
	struct addrinfo hints = {
		.ai_flags = 0,
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
	};
	struct addrinfo *ret;
	int r;

	r = getaddrinfo(addrp, port, &hints, &ret);

	if (r < 0)
		die("host lookup failed: %s\n", gai_strerror(r));

	if (ret->ai_family != AF_INET)
		die("lookup returned a non-IPv4 address\n");

	memcpy(&dest, ret->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(ret);

	return 0;
}

void usage(const char *s)
{
	fprintf(stderr, "ERROR: %s", s);
	fprintf(stderr, "usage: %s [-w wait_secs] [-c countdown] [-t timeout] [-n tunnel_name] [-T ttl]\n       <destination-address:destination-port> <local_peer_address>\n", executable);
	exit(EXIT_FAILURE);
}

int parse_args(int argc, char **argv)
{
	int opt, r;
	char *addrp;
	char *q;
	
#define F_DEST      0x01
#define F_LOCAL     0x02

#define _xstr(_y)       #_y
#define to_string(_x)   _xstr(_x)

	executable = argv[0];

	while ((opt = getopt(argc, argv, "w:c:t:n:T:")) != -1) {
		switch (opt) {
		case 'w':
			/* wait_secs */
			r = sscanf(optarg, "%d", &wait_secs);
			break;
		case 'c':
			/* keepalive_countdown */
			r = sscanf(optarg, "%d", &keepalive_countdown);
			break;
		case 't':
			/* keepalive_timeout */
			r = sscanf(optarg, "%d", &keepalive_timeout);
		case 'n':
			/* interface name */
			strncpy(tunnel_name, optarg, IFNAMSIZ);
			break;
		case 'T':
			/* time to live */
			sscanf(optarg, "%d", &time_to_live);
			break;
		default:
			break;			
		}
	}

	if (optind < argc) {
		q = strchr(argv[optind], ':');
		if (q) {
			*q++ = 0;
			r = lookup_dest(argv[optind], q);
		} else {
			r = lookup_dest(argv[optind], to_string(FOU_CTRL_PORT));
		}
		optind++;
	} else {
		r = -1;
	}

	if (r != 0)
		usage("bad or no destination\n");

	if (optind < argc) {
		r = sscanf(argv[optind], "%ms", &addrp);
		inet_pton(AF_INET, addrp, &laddr);
	} else {
		usage("no local peer address\n");
	}

	if (keepalive_timeout < wait_secs)
		usage("keepalive timeout must be greater that wait time\n");

	if (keepalive_countdown <= 1)
		usage("keepalive countdown should be greater than 1\n");

#undef to_string
#undef _xstr
#undef F_DEST
#undef F_LOCAL

	return 0;
}

int main(int argc, char **argv)
{
	int sd;

	parse_args(argc, argv);

	if (genl_resolve("fou", NULL) < 0)
		die("unable to resolve fou. is the 'fou' module loaded?\n");

	sd = init_socket();
	while (1) {		
		send_request(sd);
		if (wait_for_ack(sd))
			break;
	}

	close(sd);

	set_signal_handler();
	set_up_tunnel();
	
	keepalive();

	clean_up_tunnel();
	printf ("all done\n");

	return 0;
}

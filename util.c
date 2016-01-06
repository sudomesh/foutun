/*
 * Author: Alex Papazoglou <alex@sudomesh.org>
 */
#include "foutun.h"

void die(const char *fmt, ...)
{
	va_list v;

	va_start(v, fmt);
	vfprintf(stderr, fmt, v);
	va_end(v);
	exit(EXIT_FAILURE);
}

int get_ifindex(char *ifname)
{
	int sd, r;
	struct ifreq ifr;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd<0)
		die("can't open socket\n");


	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	r = ioctl(sd, SIOCGIFINDEX, &ifr);
	if (r<0)
		die("can't get ifindex of '%s'\n", ifname);

	close(sd);
	return ifr.ifr_ifindex;
}

int parse_address_port(const char *s, __u32 *addr, __u16 *port)
{
	char *p = strchr(s, ':');

	if (!p)
		return -1;
	*p++ = 0;
	inet_pton(AF_INET, s, addr);
	*port = htons(atoi(p));
	return 0;
}


void straddrport(char *s, struct in_addr *addr, __u16 port, int len)
{
	char buf[40];

	if (!inet_ntop(AF_INET, addr, buf, len)) {
		snprintf(s, len, "?:?");
		return;
	}

	snprintf(s, len, "%s:%d", buf, port);
}

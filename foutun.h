#ifndef FOUTUN_H
#define FOUTUN_H

#include <arpa/inet.h>
#include <asm/types.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <linux/ip.h>

#ifndef BUNDLED_INCLUDES
#include <linux/if_tunnel.h>
#else
#include "if_tunnel.h"
#endif

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#include <asm/types.h>

#ifndef BUNDLED_INCLUDES
#include <linux/fou.h>
#else
#include "fou.h"
#endif

struct msg {
	uint8_t type;
	union {
		struct {
			uint32_t peeraddr;
			uint16_t peerport;
			uint32_t tunnelkey;
		} reply;
		struct {
			uint32_t peeraddr;
		} request;
		struct {
			uint32_t token;
		} keepalive;
	} un;
};

enum {
	MSG_REQUEST = 1,
	MSG_REPLY,
	MSG_KEEPALIVE,
};


struct foutun {
	__u16 sport;
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
	__u8 pmtudisc;
	__u8 ttl;
	__u8 tos;
	__u32 ifindex;
	__u8 ikey[4];
	__u8 okey[4];
	struct rtnl_link_stats stats;
};

#define FOU_CTRL_PORT      54454
#define FOU_DATA_PORT      54455
#define FOU_KEEPALIVE_PORT 54456

#ifdef TRACE
#define trace(_str)           fprintf(stderr, "TRACE(%s:%d:%s) %s\n", __FILE__ , __LINE__, __FUNCTION__, _str)
#else
#define trace(_str)
#endif

/* netlink.c */
int if_tunnel_new(const char *tunnel_name, struct foutun *f);
int if_tunnel_del(const char *tunnel_name);
int fou_port_add(__u16 port);
int fou_port_del(__u16 port);
int if_tunnel_up(const char *ifname);
int if_addr_add(int ifindex, __u32 laddr, __u32 raddr);
int if_tunnel_get(const char *tunnel_name, struct foutun *f);
int genl_resolve(const char *, __u16 *);

/* util.c */
void die(const char *, ...);
int get_ifindex(char *ifname);
void straddrport(char *s, struct in_addr *addr, __u16 port, int len);
int parse_address_port(const char *s, __u32 *addr, __u16 *port);

/* msg.c */
int parse_message(void *, int, struct msg *);
int compose_message(void *, int, struct msg *);

#endif

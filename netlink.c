/*
 * Author: Alex Papazoglou <alex@sudomesh.org>
 */

#include "foutun.h"
#include "fou.h"

struct rtattr *addattr_l(struct nlmsghdr *n, int type, const void *data, int alen)
{
	struct rtattr *rta = (struct rtattr *)( ((char *)n) +  NLMSG_ALIGN(n->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(alen);

	if (alen > 0)
		memcpy(RTA_DATA(rta), data, alen);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(alen));
	return rta;
}

struct rtattr *addattr_u32(struct nlmsghdr *n, int type, __u32 data)
{
	return addattr_l(n, type, &data, 4);
}

struct rtattr *addattr_u16(struct nlmsghdr *n, int type, __u16 data)
{
	return addattr_l(n, type, &data, 2);
}

struct rtattr *addattr_u8(struct nlmsghdr *n, int type, __u8 data)
{
	return addattr_l(n, type, &data, 1);
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int type)
{
	return addattr_l(n, type, NULL, 0);
}

void addattr_unnest(struct nlmsghdr *n, struct rtattr *rta)
{
	rta->rta_len = ((char *)n + NLMSG_ALIGN(n->nlmsg_len)) - (char *)rta;
}


int nl_talk(struct nlmsghdr *msg, struct nlmsghdr *reply, int proto, __u16 flags)
{
	int fd;
	struct sockaddr_nl nla;
	char buf[2048];	
	struct nlmsghdr *rh;
	socklen_t len;
	int r;

	fd = socket(AF_NETLINK, SOCK_DGRAM, proto);
	if (fd < 0)
		die("can't open netlink socket\n");
	

recv_reply:
	nla.nl_family = AF_NETLINK;
	nla.nl_pid = 0;
	nla.nl_groups = 0;

	if (reply == NULL)
		msg->nlmsg_flags |= NLM_F_ACK;

	msg->nlmsg_flags |= flags;

	r = sendto(fd, msg, msg->nlmsg_len, 0, (struct sockaddr *)&nla, sizeof(nla));	
	if (r<0)
		die("can't talk to netlink\n");

	len = sizeof(nla);

	if (nla.nl_pid != 0)
		goto recv_reply;

	while (1) {
		r = recvfrom(fd, buf, 2048, 0, (struct sockaddr *)&nla, &len);
		if (r<0)
			die("can't receive from netlink\n");

		for (rh=(struct nlmsghdr *)buf;r>sizeof(struct nlmsghdr);) {
			if (nla.nl_pid != 0)
				continue;

			if (rh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rh);
				return err->error;
			}

			if (reply) {
				memcpy(reply, rh, rh->nlmsg_len);
				return 0;
			}
		}
	}
		
	close(fd);
}

int if_tunnel_del(const char *tunnel_name)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char data[256];
	} req = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_DELLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.i = {
			.ifi_family = AF_UNSPEC,
			.ifi_change = 0,
			.ifi_index = 0,
			
		},
	};

	addattr_l(&req.n, IFLA_IFNAME, tunnel_name, strlen(tunnel_name));
	return nl_talk(&req.n, NULL, NETLINK_ROUTE, 0);
}



int if_tunnel_new(const char *tunnel_name, struct foutun *f)
{
	struct rtattr *linkinfo, *infodata;
	int r;
	__u16 iflags = 0, oflags = 0;

	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char data[256];
	} req = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_NEWLINK,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
		},
		.i = {
			.ifi_family = AF_UNSPEC,
			.ifi_change = 0,
			.ifi_index = 0,
			
		},
	};

	addattr_l(&req.n, IFLA_IFNAME, tunnel_name, strlen(tunnel_name));

	linkinfo = addattr_nest(&req.n, IFLA_LINKINFO);

	addattr_l(&req.n, IFLA_INFO_KIND, "gre", 3);

	infodata = addattr_nest(&req.n, IFLA_INFO_DATA);

	addattr_u32(&req.n, IFLA_GRE_LOCAL, f->saddr);
        addattr_u16(&req.n, IFLA_GRE_ENCAP_SPORT, f->sport);
        addattr_u32(&req.n, IFLA_GRE_REMOTE, f->daddr);
        addattr_u16(&req.n, IFLA_GRE_ENCAP_DPORT, f->dport);
        addattr_u16(&req.n, IFLA_GRE_ENCAP_TYPE, TUNNEL_ENCAP_FOU);

	if (*(__u32 *)&f->ikey) {
		addattr_l(&req.n, IFLA_GRE_IKEY, f->ikey, 4);
		iflags |= GRE_KEY;
		fprintf(stderr, "ikey: %02x:%02x:%02x:%02x\n",
			f->ikey[0], f->ikey[1], f->ikey[2], f->ikey[3]);
	}

	if (*(__u32 *)f->okey) {
		addattr_l(&req.n, IFLA_GRE_OKEY, f->okey, 4);
		oflags |= GRE_KEY;
		fprintf(stderr, "okey: %02x:%02x:%02x:%02x\n",
			f->okey[0], f->okey[1], f->okey[2], f->okey[3]);
	}

	if (f->ifindex)
		addattr_u32(&req.n, IFLA_GRE_LINK, f->ifindex);

	if (f->ttl)
		addattr_u8(&req.n, IFLA_GRE_TTL, f->ttl);

	if (f->tos)
		addattr_u8(&req.n, IFLA_GRE_TOS, f->tos);

        addattr_u8(&req.n, IFLA_GRE_PMTUDISC, f->pmtudisc);

	addattr_l(&req.n, IFLA_GRE_IFLAGS, &iflags, 2);
	addattr_l(&req.n, IFLA_GRE_OFLAGS, &oflags, 2);

	addattr_unnest(&req.n, infodata);
	addattr_unnest(&req.n, linkinfo);

	trace("before");
	r = nl_talk(&req.n, NULL, NETLINK_ROUTE, 0);
	trace("after");

	if (r < 0)
		return r;

	return r;
}

int if_tunnel_get(const char *tunnel_name, struct foutun *f)
{
	int r;
	int len;
	struct rtattr *rta;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char data[2048];
	} msg = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.i = {
			.ifi_family = AF_UNSPEC,
			.ifi_change = 0,
			.ifi_index = 0,
			
		},
	};

	trace("in");
	addattr_l(&msg.n, IFLA_IFNAME, tunnel_name, strlen(tunnel_name));

	r = nl_talk(&msg.n, &msg.n, NETLINK_ROUTE, 0);
	if (r < 0)
		return r;

	if (msg.n.nlmsg_type != RTM_NEWLINK)
		die("bad netlink reply\n");

	len = msg.n.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

	for (rta=(struct rtattr *)&msg.data;RTA_OK(rta, len);rta=RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
		case IFLA_IPTUN_LOCAL:
			f->saddr = *(__u32 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_ENCAP_SPORT:
			f->sport = *(__u16 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_REMOTE:
			f->daddr = *(__u32 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_ENCAP_DPORT:
			f->dport = *(__u16 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_LINK:
			f->ifindex = *(__u32 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_TTL:
			f->ttl = *(__u8 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_TOS:
			f->tos = *(__u8 *)RTA_DATA(rta);
			break;
		case IFLA_IPTUN_PMTUDISC:
			f->pmtudisc = *(__u8 *)RTA_DATA(rta);
			break;
		case IFLA_STATS:
			memcpy(&f->stats, RTA_DATA(rta), sizeof(struct rtnl_link_stats));
		default:
			break;
		}
	}

	trace("out");
	return 0;
}


int genl_resolve(const char *name, __u16 *family)
{
	int r;
	struct rtattr *rta;
	int len;
	
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char data[256];
	} msg = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)),
			.nlmsg_type = GENL_ID_CTRL,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.g = {
			.cmd = CTRL_CMD_GETFAMILY,
			.version = 0
		},
	};

	addattr_l(&msg.n, CTRL_ATTR_FAMILY_NAME, name, strlen(name)+1);

	r = nl_talk(&msg.n, &msg.n, NETLINK_GENERIC, 0);

	if (!family)
		return r;

	if (msg.n.nlmsg_type != GENL_ID_CTRL || msg.g.cmd != CTRL_CMD_NEWFAMILY)
		die("bad netlink reply\n");

	len = msg.n.nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	for (rta=(struct rtattr *)&msg.data;RTA_OK(rta, len);rta=RTA_NEXT(rta, len)) {
		if (rta->rta_type == CTRL_ATTR_FAMILY_ID) {
			*family = *(__u16 *)RTA_DATA(rta);
			return 0;
		}
	}

	return -1;
}

static int fou_port_op(__u8 cmd, __u16 port)
{
	int r;
	__u16 fou_id;

	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char data[128];
	} msg = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)),
			.nlmsg_type = 0,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.g = {
			.cmd = cmd,
			.version = 0,
		}
	};


	r = genl_resolve("fou", &fou_id);
	if (r <0)
		die("couldn't resolve\n");

	msg.n.nlmsg_type = fou_id;

	addattr_u16(&msg.n, FOU_ATTR_PORT, port);
	if (cmd != FOU_CMD_DEL) {
		addattr_u8(&msg.n, FOU_ATTR_TYPE, FOU_ENCAP_DIRECT);
		addattr_u8(&msg.n, FOU_ATTR_IPPROTO, IPPROTO_GRE);
	}

	r = nl_talk(&msg.n, NULL, NETLINK_GENERIC, NLM_F_ACK);

	return r;
}

int fou_port_add(__u16 port)
{
	return fou_port_op(FOU_CMD_ADD, port);
}

int fou_port_del(__u16 port)
{
	return fou_port_op(FOU_CMD_DEL, port);
}

int if_addr_add(int ifindex, __u32 laddr, __u32 raddr)
{
	int r;

	struct {
		struct nlmsghdr n;
		struct ifaddrmsg i;
		char buf[1024];
	} msg = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
			.nlmsg_type = RTM_NEWADDR,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
		},
		.i = {
			.ifa_family = AF_INET,
			.ifa_prefixlen = 32,
			.ifa_flags = 0,
			.ifa_scope = RT_SCOPE_UNIVERSE,
			.ifa_index = ifindex,
		},
	};

	addattr_u32(&msg.n, IFA_LOCAL, laddr);
	
	if (raddr)
		addattr_u32(&msg.n, IFA_ADDRESS, raddr);
	
	r = nl_talk(&msg.n, NULL, NETLINK_ROUTE, 0);

	return r;
}

int if_tunnel_up(const char *ifname)
{
	struct ifreq ifr;
	int sd, r = 0;	

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		return sd;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	r = ioctl(sd, SIOCGIFFLAGS, &ifr);
	if (r < 0) 
		goto out;

	ifr.ifr_flags |= IFF_UP;
	r = ioctl(sd, SIOCSIFFLAGS, &ifr);
	if (r < 0) 
		goto out;

out:
	close(sd);
	return r;
}

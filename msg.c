/* 
 * A simple type-length-value encapsulation.
 *
 * To extend this, add to the MSG_* enum, and to the switches
 * in parse_tlv, put_tlv. Edit the msg struct and the compose
 * and parse functions accordingly.
 *
 * Author: Alex Papazoglou <alex@sudomesh.org>
 */
#include "foutun.h"

#define TLV_TYPE(_x)   (*(uint8_t *)_x)
#define TLV_LEN(_x)    (*(uint16_t *)(_x+1))
#define TLV_DATA(_x)   ((void *)((char *)_x + 3))

#if 0
/* 
 * Useful for sub-tlvs. Not in use now.
 */
static void *open_tlv(uint8_t type, void *parent, int maxlen)
{
	void *tlv = ((char *)parent + TLV_LEN(parent));

	if (maxlen < TLV_LEN(parent) + 3)
		return 0;

	TLV_TYPE(tlv) = type;
	TLV_LEN(tlv) = 0;

	return tlv;
}
#endif

static void close_tlv(void *parent, void *tlv)
{
	/* convert to big-endian */
	TLV_LEN(tlv) = htons(TLV_LEN(tlv));
	if (parent)
		TLV_LEN(parent) +=  (char *)tlv - (char *)parent;
}

int parse_tlv(void *tlv, const char *fmt, ...)
{
	va_list v;
	const char *p;
	char *q, *end;

	va_start(v, fmt);
	q = TLV_DATA(tlv);

	/* CAUTION: TLV_LEN is big-endian when parsing */
	end = (char *)TLV_DATA(tlv) + ntohs(TLV_LEN(tlv));	

	for (p=fmt;*p;p++) {
		void *arg = va_arg(v, void *);

		switch (*p) {
		case 'b':	/* 8-bit */
			if (end - q < 1)
				goto overflow;			
			*(uint8_t *)arg = *q++;
			break;			
		case 's':	/* 16-bit*/
			if (end - q < 2)
				goto overflow;
			*(uint16_t *)arg = ntohs(*(uint16_t *)q);
			q += 2;
			break;
		case 'l':	/* 32-bit */
			if (end - q < 4)
				goto overflow;		       
			*(uint32_t *)arg = ntohl(*(uint32_t *)q);
			q += 4;
			break;
		case '4':	/* IPv4 address, no conversion */
			if (end - q < 4)
				goto overflow;			
			memcpy(arg, q, 4);
			q +=  4;
			break;
		default:
			fprintf(stderr, "bad format\n");			
			return -1;
		}
	}

	va_end(v);
	return 0;

overflow:
	fprintf(stderr, "overflow\n");
	return -1;       
}

int put_tlv(void *tlv, int maxlen, const char *fmt, ...)
{
	va_list v;
	const char *p;
	char *dst;
	uint16_t idx = TLV_LEN(tlv);

	va_start(v, fmt);
	dst = (char *)TLV_DATA(tlv);

	for (p=fmt;*p;p++) {
		void *arg = va_arg(v, void *);

		switch (*p) {
		case 'b':
			if (idx >= maxlen)
				return -1;

			dst[idx++] = *(uint8_t *)arg;
			break;
		case 's':
			if (idx >= maxlen - 2)
				return -1;
			
			*(uint16_t *)(dst + idx) = htons(*(uint16_t *)arg);
			idx += 2;
			break;
		case 'l':
			if (idx >= maxlen - 4)
				return -1;
			
			*(uint32_t *)(dst + idx) = htonl(*(uint32_t *)arg);
			idx += 4;
			break;
		case '4':
			if (idx >= maxlen - 4)
				return -1;
			
			*(uint32_t *)(dst + idx) = *(uint32_t *)arg;
			idx += 4;
			break;
		default:			
			return -1;
			break;
		}
	}

	TLV_LEN(tlv) = idx;
	return 0;
}

int compose_message(void *tlv, int maxlen, struct msg *m)
{
	int len;
	
	/* the parent TLV must be made "by hand" */
	TLV_TYPE(tlv) = m->type;
	TLV_LEN(tlv) = 0;

	switch (m->type) {
	case MSG_REQUEST:
		put_tlv(tlv, maxlen, "4", &m->un.request.peeraddr);
		break;		
	case MSG_REPLY:
		put_tlv(tlv, maxlen, "4sl", &m->un.reply.peeraddr, &m->un.reply.peerport,
			&m->un.reply.tunnelkey);
		break;
	case MSG_KEEPALIVE:
		put_tlv(tlv, maxlen, "l", &m->un.keepalive.token);
		break;
	default:
		break;
	}

	len = TLV_LEN(tlv) + 3;
	close_tlv(NULL, tlv);	

	return len;
}

int parse_message(void *tlv, int len, struct msg *m)
{
	if (len < 3 || (ntohs(TLV_LEN(tlv)) > len - 3))
		return -1;	

	m->type = TLV_TYPE(tlv);
	
	switch (TLV_TYPE(tlv)) {
	case MSG_REQUEST:
		parse_tlv(tlv, "4", &m->un.request.peeraddr);
		break;
	case MSG_REPLY:
		parse_tlv(tlv, "4sl", &m->un.reply.peeraddr, &m->un.reply.peerport,
			&m->un.reply.tunnelkey);
		break;		
	case MSG_KEEPALIVE:
		parse_tlv(tlv, "l", &m->un.keepalive.token);
		break;		
	default:
		printf ("bogus message of type %d\n", TLV_TYPE(tlv));
		return -1;
	}
	
	return 0;
}

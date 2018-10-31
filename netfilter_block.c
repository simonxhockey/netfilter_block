#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char *cmp;

struct ip_addr {
	u_int8_t s_ip[4];
};

struct ip_header {
	u_int8_t ip_v_hl;		/* version + header length */
	u_int8_t ip_tos;		/* type of service */
	u_int16_t ip_len;		/* total length */
	u_int16_t ip_id;		/* identification */
	u_int16_t ip_off;		/* fragment offset field */
	u_int8_t ip_ttl;		/* time to live */
	u_int8_t ip_p;		/* protocol */
	u_int16_t ip_sum;		/* checksum */
	struct ip_addr ip_src, ip_dst;		/* source and dest address */
};

struct tcp_header {
	u_int16_t th_sport;		/* source port */
	u_int16_t th_dport;		/* destination port */
	u_int32_t th_seq;		/* sequence number */
	u_int32_t th_ack;		/* acknowledgement number */
	u_int8_t th_off_x2;		/* data offset + unused */
	u_int8_t  th_flags;		/* control flags */
	u_int16_t th_win;		/* window */
	u_int16_t th_sum;		/* checksum */
	u_int16_t th_urp;		/* urgent pointer */
};

void usage(){
	printf("syntax: netfilter_block <host>\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	int ret;
	unsigned char *packet;
	ret = nfq_get_payload(nfa, &packet);
	char *str_get = "GET";
	char *str_post = "POST";
	char *str_head = "HEAD";
	char *str_put = "PUT";
	char *str_delete = "DELETE";
	char *str_options = "OPTIONS";
	char *str_host = "Host";
	char *tmp;
	if (ret >= 0) {
		struct ip_header* ip_hdr = (struct ip_header *)(packet);
		u_int8_t ip_hdr_len = (ip_hdr->ip_v_hl & 0xf) * 4;
	
		/* if it is tcp */
		if(ip_hdr->ip_p == 6) {
			struct tcp_header* tcp = (struct tcp_header *)(packet + ip_hdr_len);
			u_int16_t tcp_hdr_len = ((tcp->th_off_x2 & 0xf0)>>4) * 4;
			
			u_int16_t tcp_len = ntohs(ip_hdr->ip_len) - ip_hdr_len;
			u_int16_t tcp_payload_len = tcp_len - tcp_hdr_len ;
			u_int8_t *tcp_payload = (u_int8_t *)packet + ip_hdr_len + tcp_hdr_len;

			if(tcp_payload_len == 0) {
				printf("It is no tcp_data here.\n");
			}
			else {
				printf("It is tcp_data here.\n");

				if(memcmp(tcp_payload, str_get, strlen(str_get)) == 0 || memcmp(tcp_payload, str_post, strlen(str_post)) == 0 || memcmp(tcp_payload, str_head, strlen(str_head)) == 0 || memcmp(tcp_payload, str_put, strlen(str_put)) == 0 || memcmp(tcp_payload, str_delete, strlen(str_delete)) == 0 || memcmp(tcp_payload, str_options, strlen(str_options)) == 0) {
					
					for(int i = 0; i < tcp_payload_len; i++) {
						if(tcp_payload[i] == 13 && tcp_payload[i+1] == 10) {  // if there is CRLF
							char *tcp_host = tcp_payload+i+2;
							if(memcmp(tcp_host, str_host, strlen(str_host)) == 0) {
								if (memcmp((tcp_payload+i+8), cmp, strlen(cmp)) == 0 ) {  // "Host: " + host
									for(int j = 0; j < 10; j++) printf("it is blocked\n");
									return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
								}
							}
						}
					}
				}
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{	
	if(argc != 2){
		usage();
		return -1;
	}
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	cmp = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}


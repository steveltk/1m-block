#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/types.h>
#include <libnet.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <set>
#include <ctime>

using namespace std;
set <string> malicious_sites;

struct res{
	u_int32_t id;
	int flag;
};

int check(unsigned char* buf, int size) {
	char site[1000];
	int ip4_size = (buf[0] & 0xf) * 4;
	if(ip4_size < LIBNET_IPV4_H){
		return 0;
	}
	
	int tcp_size = (buf[ip4_size+12] >> 4)*4;
	if(tcp_size < LIBNET_TCP_H){
		return 0;
	}
	
	int data = ip4_size + tcp_size;
	
	if(strncasecmp((const char*)buf + data, "GET",3)){
		return 0;
	}
	int i;
	for(i = 0; i<size;i++){
		if(!strncmp((const char*)buf + data + i, "Host: ",6)){
			break;
		}
	}
	for(int j = i + 6; j<size;j++){
		if(buf[data+j] == '\n'){
			site[j - i - 7] = '\00';
			break;
		}
		site[j-i-6] = buf[data + j];
	}
	if(malicious_sites.count(string(site))){
		printf("blocked\n");
		return 1;
	}
	else{
		for(int i=0;i<strlen(site);i++){
			if(site[i]=='.'){
				if(malicious_sites.count(string(site+1+i))){
					printf("blocked\n");
					return 1;
				}
			}
		}
		return 0;
	}
	return 0;
}


/* returns packet id */
static struct res print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	int b;
	unsigned char *data;
	struct res haha;

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
	if (ret >= 0){
		b = check(data, ret);
	}

	fputc('\n', stdout);
	haha.id = id;
	haha.flag = b;
	return haha;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct res result = print_pkt(nfa);
	if(result.flag){
		return nfq_set_verdict(qh, result.id, NF_DROP, 0, NULL);
	}
	else{
		return nfq_set_verdict(qh, result.id, NF_ACCEPT, 0, NULL);
	}
}

void usage(void){
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
}

int main(int argc, char **argv)
{
	if(argc != 2){
		usage();
		exit(1);
	}
	
	long start_time, end_time;
	start_time = clock();
	FILE *fp = fopen(argv[1], "r");
	char line[1000];
	while(fgets(line, sizeof(line), fp))
	{	
		int i;
		line[strlen(line)-1] = '\0';
		for(i=0; i<strlen(line); i++)
		{
			if(line[i] != ',') continue;
			i++;
			break;
		}
		string site(&line[i]);
		malicious_sites.insert(site);
	}
	fclose(fp);
	end_time = clock();
	printf("CLOCKS PER SEC: %ld\n", CLOCKS_PER_SEC);
	printf("%ldclocks elapsed to load list\n", end_time - start_time);
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

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
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
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

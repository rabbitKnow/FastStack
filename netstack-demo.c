/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mempool.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define SOCKETS_NUM 2
#define LCORE_NUM 40
#define MAX_MBUFS_COUNT 32


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

struct lcore_status{	

	uint8_t header_template[sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr)];
	struct rte_mbuf * mbufs[MAX_MBUFS_COUNT];
	uint16_t mbufs_count;
	uint64_t sent_count;
	uint64_t dropped_count;
};

struct system { 
	struct rte_mempool *pools[SOCKETS_NUM];
	struct lcore_status *lcore_status[LCORE_NUM];
};

struct system sys;

int print_flag;
int bit_flag;
uint32_t send_num;
uint32_t send_data;


int c2lower(int c)
{  
	int d;
	
	if (c >= 'A' && c <= 'Z')  
	{  
		d= c + 'a' - 'A';  
	}  
	else  
	{  
		d= c;  
	}
	return d;
}


uint32_t
htoi(char s[])
{  
	int i;  
	uint32_t n = 0;  
	if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))  
	{  
		i = 2;  
	}  
	else  
	{  
		i = 0;  
	}  
	for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)  
	{  
		if (c2lower(s[i]) > '9')  
		{  
			n = 16 * n + (10 + c2lower(s[i]) - 'a');  
		}  
		else  
		{  
			n = 16 * n + (c2lower(s[i]) - '0');  
		}  
	}  
	return n;  
}

void
init_header_template(uint8_t * header_template,uint8_t port ){
	memset(header_template,0,sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
	struct ether_hdr *eth = (struct ether_hdr *)header_template;
	struct ipv4_hdr *ip = (struct ipv4_hdr *)((unsigned char *)eth + sizeof(struct ether_hdr));
	struct udp_hdr *udp = (struct udp_hdr *)((unsigned char *)ip + sizeof(struct ipv4_hdr));


	/* Display the port MAC address. */
	struct ether_addr saddr;
	struct ether_addr daddr;
	rte_eth_macaddr_get(port, &saddr);
	void *tmp;
	tmp=&eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp)=0xffffffffffff;

	ether_addr_copy(&saddr, &eth->s_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	//ip->version_ihl = 0x40 | 0x05;
	//ip->type_of_service = 0;
	//ip->packet_id = 0;
	//ip->fragment_offset = 0;
	//ip->time_to_live = 64;
	//ip->next_proto_id = IPPROTO_UDP;
	//ip->hdr_checksum = 0;

	//udp->dgram_cksum = 0;
	//wait to add check sum 

}
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
	int
port_init(uint8_t port)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	//get the mbuf_pool
	uint8_t socket_id=rte_eth_dev_socket_id(port);
	struct rte_mempool *mbuf_pool=sys.pools[socket_id];

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				socket_id, NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				socket_id, NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8" %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
	void
lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	uint16_t lcore_id= rte_lcore_id();
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	init_header_template(sys.lcore_status[lcore_id]->header_template,port);

	time_t start_time;  
	start_time =time(NULL);
	/* Run until the application is quit or killed. */
	for(;;){
		int iter=0;
		//	for(;iter<200000000;iter++){
		struct rte_mbuf *mbuf= rte_pktmbuf_alloc(sys.pools[rte_socket_id()]);
		assert(sys.pools[rte_socket_id()]!=NULL);
		//assert(mbuf==NULL);

		//printf("before size of %u\n",sizeof(struct rte_mbuf));
		struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
		struct ipv4_hdr *ip = (struct ipv4_hdr *)((unsigned char *)eth + sizeof(struct ether_hdr));
		struct udp_hdr *udp = (struct udp_hdr *)((unsigned char *)ip + sizeof(struct ipv4_hdr));
		uint8_t *pkt_data=(uint8_t *)(unsigned char *)udp+sizeof(struct udp_hdr);

		rte_memcpy(eth, sys.lcore_status[lcore_id]->header_template, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

		uint64_t i=0;

		uint8_t data32[4];
		uint8_t data64[8];

		if(print_flag){
		*(uint32_t *)data32 = send_data;
		rte_memcpy(pkt_data,(uint8_t *)data32,32);
		 	
		}
		else
		{
			if(bit_flag==32)
			{
			*(uint32_t *)data32 = (i & 0xffff) | ((~i & 0xffff) << 16);
			rte_memcpy(pkt_data,(uint8_t *)data32,32);
			}
			else
			{
			*(uint64_t *)data64 = (i & 0xffffffff) | ((~i & 0xffffffff) << 32);
			rte_memcpy(pkt_data,(uint8_t *)data64,64);
			}

		}
		//*(uint32_t *)data = (i & 0xffff) | ((~i & 0xffff) << 16);

		//rte_memcpy(pkt_data,(uint8_t *)data,32);
		size_t pkt_size;
		pkt_size=sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr)+sizeof(uint8_t)*4;

		mbuf->data_len=pkt_size;
		mbuf->pkt_len=pkt_size;
		//need add data !!!!!!!!!!!!!!!!!
		sys.lcore_status[lcore_id]->mbufs[sys.lcore_status[lcore_id]->mbufs_count]=mbuf;
		sys.lcore_status[lcore_id]->mbufs_count=sys.lcore_status[lcore_id]->mbufs_count+1;

		//printf("add to buf count is%u\n",sys.lcore_status[lcore_id]->mbufs_count);

		if(sys.lcore_status[lcore_id]->mbufs_count==MAX_MBUFS_COUNT){

			uint16_t test_i=0;
			uint16_t index=0;

			uint8_t * packet= rte_pktmbuf_mtod(sys.lcore_status[lcore_id]->mbufs[0], uint8_t *); 
			if(print_flag){

			   for(;index<sizeof(struct rte_mbuf);index++){

			   printf(" %02x ",packet[index]);
			
			   }
			   printf("\n");
			}
			uint16_t count=rte_eth_tx_burst(port, 0 , sys.lcore_status[lcore_id]->mbufs, sys.lcore_status[lcore_id]->mbufs_count);
			sys.lcore_status[lcore_id]->sent_count+=count;
			sys.lcore_status[lcore_id]->dropped_count+=(uint64_t)MAX_MBUFS_COUNT-count;

			for(;count<MAX_MBUFS_COUNT;count++)
				rte_pktmbuf_free(sys.lcore_status[lcore_id]->mbufs[count]);

			sys.lcore_status[lcore_id]->mbufs_count=0;
			//printf("sent count=%u,droped count=%u\n",sys.lcore_status[lcore_id]->sent_count,sys.lcore_status[lcore_id]->dropped_count);
			//	printf("send\n");
			//	sleep(5);
		}

		if(sys.lcore_status[lcore_id]->sent_count>=send_num){

			time_t end_time;  
			end_time =time(NULL);
			int dul_time=end_time-start_time;
			dul_time++;
			printf("dul time=%d s",dul_time);
			return ;
		}

		//	}
		//	printf("200000000\n");
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
	int
init(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	int opt;

	static struct option lgopts[] = {
		{"send", 1, 0, 0},
		{"num", 1, 0, 0},
		{"size",1, 0, 0},
		{NULL, 0, 0, 0}
		};

	char **argvopt;

	int option_index;
	char *prgname = argv[0];

	print_flag=0;
	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
					lgopts, &option_index)) != EOF) {

		switch (opt) {
			/* long options */
			case 0:
				if (!strcmp(lgopts[option_index].name, "send")) {
				send_data=htoi(optarg);
				send_num=4;
				print_flag=1;
				bit_flag=0;

				printf("send%u\n",send_data);
				}
				if (!strcmp(lgopts[option_index].name, "num")) {
				send_num=atoi(optarg);
				printf("num%u\n",send_num);
				}
				if (!strcmp(lgopts[option_index].name, "size")) {
				bit_flag=atoi(optarg);
				printf("size%u\n",bit_flag);
				}
				break;
			default:
				return -1;
		}}

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();

	int i=0;
	for(;i<LCORE_NUM;i++){
		sys.lcore_status[i]=(struct lcore_status *)malloc(sizeof(struct lcore_status));
		sys.lcore_status[i]->mbufs_count=0;
		sys.lcore_status[i]->sent_count=0;
		sys.lcore_status[i]->dropped_count=0;

	}

	/* Numa aware  initialize mempool */
	unsigned socket, lcore;

	/* Init the buffer pools */
	for (socket = 0; socket < SOCKETS_NUM; socket ++) {
		char name[32];

		snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
		printf("Creating the mbuf pool for socket %u ...\n", socket);
		sys.pools[socket] = rte_pktmbuf_pool_create(
				name, NUM_MBUFS * nb_ports,
				MBUF_CACHE_SIZE,
				0, RTE_MBUF_DEFAULT_BUF_SIZE, socket);
		if (sys.pools[socket] == NULL) {
			rte_panic("Cannot create mbuf pool on socket %u\n", socket);
		}   
	}   

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	uint8_t lcore_count=rte_lcore_count();
	printf("lcore total used is %u \n",lcore_count);

	/* Call lcore_main on the master core only. */
	//	lcore_main();

	return 0;
}



int main(int argc, char *argv[]){
	init(argc,argv);

	/*Launch per-lcore init on every lcore*/
	rte_eal_mp_remote_launch(lcore_main,NULL,CALL_MASTER);
	uint32_t lcore;
	RTE_LCORE_FOREACH_SLAVE(lcore){
		if(rte_eal_wait_lcore(lcore) < 0){
			return -1;
		}

	}
	return 0;
}

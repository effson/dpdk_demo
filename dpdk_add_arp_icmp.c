// 增加处理 arp和icmp协议的代码
#include<stdio.h>
#include<unistd.h>
#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>

#include<arpa/inet.h>

#define NUM_MBUFS (4096 - 1)
#define BURST_SIZE 32

#define ENABLE_SEND 1

// ------------------------------------------------------------------------------------------------------
#define ENABLE_ARP  1
#define ENABLE_ICMP  1
// ------------------------------------------------------------------------------------------------------
// src_mac, dst_mac    src_ip, dst_ip    src_port,dst_port

#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))
static uint32_t globalIP =  MAKE_IPV4_ADDR(192, 168, 1, 101);


static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint8_t gSrcIP;
static uint8_t gDstIP;

static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static void dpdk_init_port(struct rte_mempool *mbuf_pool){

	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if(nb_sys_ports == 0){
		rte_exit(EXIT_FAILURE,"No eth Dev!\n");
	}
	printf("nb_sys_ports : %d\n", nb_sys_ports);

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);

	const int num_rx_queues = 1;  // max:8
	const int num_tx_queues = 1;
	struct rte_eth_conf port_conf = port_conf_default;
	if(rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf) < 0){
		rte_exit(EXIT_FAILURE,"Cound Not Configure!\n");
	}

	if(rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), 
		NULL, mbuf_pool) < 0){
		
		rte_exit(EXIT_FAILURE,"Cound Not Set RX queue!\n");
	}
		
#if ENABLE_SEND
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads; 
	if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), 
		&txq_conf) < 0){
		
		rte_exit(EXIT_FAILURE,"Cound Not Set TX queue!\n");
	}
#endif

	if(rte_eth_dev_start(gDpdkPortId) < 0){
		rte_exit(EXIT_FAILURE,"Cound Not Start!\n");
	}
	
}


static int dpdk_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_length){

	// ether 以太网头部
	struct rte_ether_hdr* eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// iphdr ip头部
	struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	iphdr->version_ihl = 0x45;
	iphdr->type_of_service = 0;
	iphdr->total_length = htons(total_length - sizeof(struct rte_ether_hdr));
	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live = 64; //ttl
	iphdr->next_proto_id = IPPROTO_UDP;
	iphdr->src_addr = gSrcIP;
	iphdr->dst_addr = gDstIP;

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	// UDP 头部
	struct rte_udp_hdr* udphdr = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udphdr->src_port = gSrcPort;
	udphdr->dst_port = gDstPort;
	uint16_t udp_len = total_length - sizeof(struct rte_ether_hdr) -sizeof(struct rte_ipv4_hdr);
	udphdr->dgram_len = htons(udp_len);

	rte_memcpy((uint8_t *)(udphdr + 1), data, udp_len - sizeof(struct rte_udp_hdr));

	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

	struct in_addr addr;
	addr.s_addr = gSrcIP;
	printf(" --> src: %s : %d, ", inet_ntoa(addr), ntohs(gSrcPort));

	addr.s_addr = gSrcIP;
	printf(" <-- dst: %s : %d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}





// begin------------------------------------------------------------------------------------------------------
#if ENABLE_ARP

static int dpdk_encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip){

	struct rte_ether_hdr* eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1); 
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	// 以太网 MAC 地址的长度是 6 字节
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	// IPv4 协议地址长度为 4 字节
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(2);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return 0;
}

static struct rte_mbuf *dpdk_send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip){

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"Error with mbuf alloc!\n");
	}
	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
	dpdk_encode_arp_pkt(pkt_data, dst_mac, sip, dip);

	return mbuf;
}

#endif
//end ------------------------------------------------------------------------------------------------------




static struct rte_mbuf *dpdk_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length){
	/*
	Ethernet	struct rte_ether_hdr	14 字节
	IPv4	struct rte_ipv4_hdr			20 字节
	UDP	struct rte_udp_hdr				8 字节
	*/

	const unsigned total_length = length + 42;
	
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"Error with mbuf alloc!\n");
	}
	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	dpdk_encode_udp_pkt(pktdata, data, total_length);

	return mbuf;
}




// begin------------------------------------------------------------------------------------------------------
#if ENABLE_ICMP

// icmp checksum 实现
static uint16_t dpdk_icmp_checksum (uint16_t *addr, int count) {

	register long sum = 0;
	while(count > 1) {
		sum += *(unsigned short *) addr ++;
		count -= 2; 
	}

	if (count > 0) {
		sum += *(unsigned short *) addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

static int dpdk_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, 
											uint16_t id, uint16_t seq_nb) {
	struct rte_ether_hdr* eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	iphdr->version_ihl = 0x45;
	iphdr->type_of_service = 0;
	iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live = 64; //ttl
	iphdr->next_proto_id = IPPROTO_ICMP;
	iphdr->src_addr = sip;
	iphdr->dst_addr = dip;

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	//icmp
	struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr));
	icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmphdr->icmp_code = 0;
	icmphdr->icmp_ident = id;
	icmphdr->icmp_seq_nb = seq_nb;

	icmphdr->icmp_cksum = 0;
	icmphdr->icmp_cksum = dpdk_icmp_checksum(icmphdr, sizeof(struct rte_icmp_hdr *); 

	return 0;
}

static struct rte_mbuf *dpdk_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seq_nb) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"Error with mbuf alloc!\n");
	}	
	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
	dpdk_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seq_nb);

	return mbuf;
}

#endif
// end------------------------------------------------------------------------------------------------------




int main(int argc, char* argv[]){
	if(rte_eal_init(argc, argv) < 0){
		rte_exit(EXIT_FAILURE,"Error with EAL init!\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0, 0, 
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(mbuf_pool == NULL){
		rte_exit(EXIT_FAILURE,"Cound Not Create mbuf pool!\n");
	}

	dpdk_init_port(mbuf_pool);

	struct rte_ether_addr mac;
    rte_eth_macaddr_get(gDpdkPortId, &mac);
    printf("Port MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
         mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
         mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
	
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)gSrcMac);
	printf("dev start success\n");
	
	while(1){

		struct rte_mbuf *mbufs[BURST_SIZE]; 
		unsigned nb_recv = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if(nb_recv > 0){
			printf("recv %u packets\n", nb_recv);
		}
		if (nb_recv > BURST_SIZE){
			rte_exit(EXIT_FAILURE,"Error with rte_eth_rx_burst!\n");
		}
/*----------------------------------------------------------
	|	ethhdr  |   iphdr  |  udphdr/tcphdr   |   payload  |
  ----------------------------------------------------------
*/
		unsigned i = 0;
		for(i = 0;i < nb_recv; i ++){
			
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);

      
// begin------------------------------------------------------------------------------------------------------
      
#if ENABLE_ARP

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				
				struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, 
					sizeof(struct rte_ether_hdr));
				
				struct in_addr addr;
				addr.s_addr = arphdr->arp_data.arp_sip;
				printf("src: %s ", inet_ntoa(addr));

				addr.s_addr = globalIP; //gSrcIP
				printf("dst: %s\n", inet_ntoa(addr));
				if (arphdr->arp_data.arp_tip == globalIP) { //gSrcIP
					
					struct rte_mbuf *arpbuf = dpdk_send_arp(mbuf_pool, arphdr->arp_data.arp_sha.addr_bytes, 
						arphdr->arp_data.arp_tip, arphdr->arp_data.arp_sip);
					rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
					rte_pktmbuf_free(arpbuf);
					
					rte_pktmbuf_free(mbufs[i]);
					
				}

				continue;
			}
#endif
//end ------------------------------------------------------------------------------------------------------


      
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				continue;
			}

			struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if(iphdr->next_proto_id == IPPROTO_UDP){
				
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

#if ENABLE_SEND

				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

				rte_memcpy(&gSrcIP, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&gDstIP, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
				
#endif

				uint16_t length = ntohs(udphdr->dgram_len);
				*((char *)udphdr + length) = '\0';

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s : %d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = gSrcIP;
				printf("dst: %s : %d\n", inet_ntoa(addr), ntohs(udphdr->dst_port));
				
#if ENABLE_SEND
				
				struct rte_mbuf *txbuf = dpdk_send_udp(mbuf_pool, (uint8_t *)(udphdr + 1), length);
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
				rte_pktmbuf_free(txbuf);
				
#endif

				rte_pktmbuf_free(mbufs[i]);
			}
// ------------------------------------------------------------------------------------------------------			
#if ENABLE_ICMP

			if (iphdr->next_proto_id == IPPROTO_ICMP) {
				struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
				if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
					struct rte_mbuf *icmpbuf = dpdk_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, 
						iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
					rte_eth_tx_burst(gDpdkPortId, 0, &icmpbuf, 1);
					rte_pktmbuf_free(txbuf);

					rte_pktmbuf_free(mbufs[i]);
				}
			}

#endif
// ------------------------------------------------------------------------------------------------------
		}
	}	
}


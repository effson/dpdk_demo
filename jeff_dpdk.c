#include<stdio.h>
#include<unistd.h>
#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>

#include<arpa/inet.h>

#define NUM_MBUFS 2048
#define BURST_SIZE 128

#define ENABLE_SEND 1
// src_mac, dst_mac    src_ip, dst_ip    src_port,dst_port

#if ENABLE_SEND

uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

uint8_t gSrcIP;
uint8_t gDstIP;

uint16_t gSrcPort;
uint16_t gDstPort;

#endif

static int dpdk_encode_udp_pkt(uint8_t *msg, char *data, uint16_t total_length){

	// ether 以太网头部
	struct rte_ether_hdr* eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// iphdr ip头部
	struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr *)(eth + 1);
	iphdr->version_ihl = 0x54;
	iphdr->type_of_service = 0x0;
	iphdr->total_length = htons(total_length - sizeof(struct rte_ether_hdr));
	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	iphdr->next_proto_id = IPPROTO_UDP;
	iphdr->src_addr = gSrcIP;
	iphdr->dst_addr = gDstIP;

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	// UDP 头部
	struct rte_udp_hdr* udphdr = (struct rte_udp_hdr *)(iphdr + 1);
	udphdr->src_port = gSrcPort;
	udphdr->dst_port = gDstPort;
	uint16_t udp_len = total_length - sizeof(struct rte_ether_hdr) -sizeof(struct rte_ipv4_hdr);
	udphdr->dgram_len = htons(udp_len);

	rte_memcpy((uint8_t *)(udphdr + 1), data, udp_len - sizeof(struct rte_udp_hdr));

	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

	return total_length;
}

static struct rte_mbuf *dpdk_send(struct rte_mempool *mbuf_pool, char *data, uint16_t length){
	const unsigned total_length = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
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


int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

int main(int argc, char* argv[]){
	if(rte_eal_init(argc, argv) < 0){
		rte_exit(EXIT_FAILURE,"Error with EAL init!\n");
	}

	uint16_t nb_sys_ports = rte_eth_dev_count_avail();

	if(nb_sys_ports == 0){
		rte_exit(EXIT_FAILURE,"No eth Dev!\n");
	}
	
	printf("nb_sys_ports : %d\n", nb_sys_ports);

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0, 0, 
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(!mbuf_pool){
		rte_exit(EXIT_FAILURE,"Cound Not Build mbuf pool!\n");
	}
	
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);

	const int num_rx_queues = 1;
	const int num_tx_queues = 0;
	struct rte_eth_conf port_conf = port_conf_default;
	if(rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf) < 0){
		rte_exit(EXIT_FAILURE,"Cound Not Configure!\n");
	}

	if(rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), 
		NULL, mbuf_pool) < 0){
		rte_exit(EXIT_FAILURE,"Cound Not Set RX queue!\n");
	}

	if(rte_eth_dev_start(gDpdkPortId) < 0){
		rte_exit(EXIT_FAILURE,"Cound Not Start!\n");
	}
	 struct rte_ether_addr mac;
     rte_eth_macaddr_get(gDpdkPortId, &mac);
     printf("Port MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
         mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
         mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);

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
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				continue;
			}

			struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			if(iphdr->next_proto_id == IPPROTO_UDP){
				
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

#if ENABLE_SEND
				rte_memcpy(gSrcMac, ehdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

				rte_memcpy(&gSrcIP, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&gDstIP, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif
				uint16_t length = ntohs(udphdr->dgram_len) - sizeof(struct rte_udp_hdr);				
				printf("length : %d, content : %s\n", length, (char *)(udphdr + 1));

				dpdk_send(mbuf_pool, (char *)(udphdr + 1), length);
			}
		}
	}
	
	return 0;
}


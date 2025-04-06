#include<stdio.h>
#include<unistd.h>
#include<rte_eal.h>
#include<rte_ethdev.h>

#include<arpa/inet.h>

#define NUM_MBUFS 2048
#define BURST_SIZE 128



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

	printf("dev start success\n");

	while(1){

		struct rte_mbuf *mbufs[BURST_SIZE]; 
		unsigned nb_recv = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
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
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPR_IPV4)){
				continue;
			}

			struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			if(iphdr->next_proto_id == IPPROTO_UDP){
				
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
				uint16_t length = udphdr->dgram_len;
				printf("length : %d, content : %s\n", length, (char *)(udphdr + 1));
			
			}
		}
	}
	
	return 0;
}

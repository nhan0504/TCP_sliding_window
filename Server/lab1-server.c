/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define PORT_NUM 4

#define MAX_FLOWS 8

/* Flags */
#define FLAG_SYN 0x01
#define FLAG_ACK 0x02
#define FLAG_FIN 0x04
#define FLAG_DATA 0x08

/* Sliding window header structure */
struct sliding_hdr {
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flow_id;
    uint16_t flags;
    uint64_t timestamp;
} __attribute__((packed));

/* Per-flow receiver state */
struct flow_recv_state {
    uint32_t expected_seq;
    uint32_t packets_received;
    uint32_t packets_acked;
    uint64_t bytes_received;
    bool active;
};

/* Flow states */
struct flow_recv_state flow_states[MAX_FLOWS];

struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_eth;

int ack_len = sizeof(struct sliding_hdr);

uint32_t checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum) {
	unsigned int i;

	/* Checksum all the pairs of bytes first. */
	for (i = 0; i < (nbytes & ~1U); i += 2) {
		sum += (uint16_t)ntohs(*((uint16_t *)(buf + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	if (i < nbytes) {
		sum += buf[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return sum;
}

uint32_t wrapsum(uint32_t sum) {
	sum = ~sum & 0xFFFF;
	return htons(sum);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0)
	{
		printf("Error during getting device (port %u) info: %s\n",
			   port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++)
	{
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
										rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, &my_eth);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		   port, RTE_ETHER_ADDR_BYTES(&my_eth));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}

/* Function to parse received packet and extract sliding window header information
 * Parameters:
 *   pkt: Pointer to the received packet (rte_mbuf)
 *   flow_id: Pointer to store extracted flow ID
 *   seq_num: Pointer to store extracted sequence number
 *   flags: Pointer to store extracted flags
 *   data_len: Pointer to store length of the data payload
 * Returns:
 *   0 on success, -1 on failure (e.g., invalid packet)
 */
static int parse_data_packet(struct rte_mbuf *pkt, uint16_t *flow_id, 
							 uint32_t *seq_num, uint16_t *flags, uint32_t *data_len) {
    uint8_t *p = rte_pktmbuf_mtod(pkt, uint8_t *);
    size_t header = 0;

    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(p);
    p += sizeof(*eth_hdr);
    header += sizeof(*eth_hdr);
    
    struct rte_ether_addr mac_addr = {};
    rte_eth_macaddr_get(1, &mac_addr);
    if (!rte_is_same_ether_addr(&mac_addr, &eth_hdr->dst_addr)) {
        return -1;
    }
    
    if (eth_hdr->ether_type != rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(p);
    p += sizeof(*ip_hdr);
    header += sizeof(*ip_hdr);

    if (ip_hdr->next_proto_id != IPPROTO_UDP) {
        return -1;
    }

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(p);
    p += sizeof(*udp_hdr);
    header += sizeof(*udp_hdr);

    struct sliding_hdr *sld_hdr = (struct sliding_hdr *)(p);
    
    *flow_id = rte_be_to_cpu_16(sld_hdr->flow_id);
    *seq_num = rte_be_to_cpu_32(sld_hdr->seq_num);
    *flags = rte_be_to_cpu_16(sld_hdr->flags);
    *data_len = pkt->pkt_len - header - sizeof(struct sliding_hdr);
    
    return 0;
}

/* Function to send ACK packets
 * Parameters:
 *   port: Port number to send the ACK from
 *   rx_pkt: Pointer to the received packet (rte_mbuf) to extract headers
 *   flow_id: Flow ID to include in the ACK
 *   ack_num: Acknowledgment number to include in the ACK
 * Returns:
 *   0 on success, -1 on failure (e.g., memory allocation failure)
 */
static int send_ack(uint16_t port, struct rte_mbuf *rx_pkt, 
                    uint16_t flow_id, uint32_t ack_num) {
    struct rte_mbuf *ack = rte_pktmbuf_alloc(mbuf_pool);
    if (ack == NULL) {
        printf("[DEBUG SERVER] Failed to allocate ACK mbuf\n");
        return -1;
    }

    size_t header_size = 0;
    uint8_t *ptr = rte_pktmbuf_mtod(ack, uint8_t *);

    // Get headers from received packet for reply
    struct rte_ether_hdr *rx_eth = rte_pktmbuf_mtod(rx_pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *rx_ip = rte_pktmbuf_mtod_offset(rx_pkt, struct rte_ipv4_hdr *,
                                                          sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *rx_udp = rte_pktmbuf_mtod_offset(rx_pkt, struct rte_udp_hdr *,
                                                          sizeof(struct rte_ether_hdr) + 
                                                          sizeof(struct rte_ipv4_hdr));

    printf("[DEBUG SERVER] Sending ACK to MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           rx_eth->src_addr.addr_bytes[0], rx_eth->src_addr.addr_bytes[1],
           rx_eth->src_addr.addr_bytes[2], rx_eth->src_addr.addr_bytes[3],
           rx_eth->src_addr.addr_bytes[4], rx_eth->src_addr.addr_bytes[5]);                                                 

    /* Ethernet header */
    struct rte_ether_hdr *eth_h_ack = (struct rte_ether_hdr *)ptr;
    rte_ether_addr_copy(&my_eth, &eth_h_ack->src_addr);
    rte_ether_addr_copy(&rx_eth->src_addr, &eth_h_ack->dst_addr);
    eth_h_ack->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
    ptr += sizeof(*eth_h_ack);
    header_size += sizeof(*eth_h_ack);

    /* IPv4 header */
    struct rte_ipv4_hdr *ip_h_ack = (struct rte_ipv4_hdr *)ptr;
    ip_h_ack->version_ihl = 0x45;
    ip_h_ack->type_of_service = 0x0;
    ip_h_ack->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + 
                                               sizeof(struct rte_udp_hdr) + ack_len);
    ip_h_ack->packet_id = rte_cpu_to_be_16(1);
    ip_h_ack->fragment_offset = 0;
    ip_h_ack->time_to_live = 64;
    ip_h_ack->next_proto_id = IPPROTO_UDP;
    ip_h_ack->src_addr = rx_ip->dst_addr;
    ip_h_ack->dst_addr = rx_ip->src_addr;

    uint32_t ipv4_checksum = wrapsum(checksum((unsigned char *)ip_h_ack, 
                                      sizeof(struct rte_ipv4_hdr), 0));
    ip_h_ack->hdr_checksum = rte_cpu_to_be_32(ipv4_checksum);
    header_size += sizeof(*ip_h_ack);
    ptr += sizeof(*ip_h_ack);

    /* UDP header */
    struct rte_udp_hdr *udp_h_ack = (struct rte_udp_hdr *)ptr;
    udp_h_ack->src_port = rx_udp->dst_port;
    udp_h_ack->dst_port = rx_udp->src_port;
    udp_h_ack->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + ack_len);
    udp_h_ack->dgram_cksum = 0;
    ptr += sizeof(*udp_h_ack);
    header_size += sizeof(*udp_h_ack);

    printf("[DEBUG SERVER] ACK UDP ports: %u -> %u\n", 
           rte_be_to_cpu_16(udp_h_ack->src_port), rte_be_to_cpu_16(udp_h_ack->dst_port));

    /* Sliding header (ACK) */
    struct sliding_hdr *sld_h_ack = (struct sliding_hdr *)ptr;
    sld_h_ack->seq_num = 0;
    sld_h_ack->ack_num = rte_cpu_to_be_32(ack_num);
    sld_h_ack->flow_id = rte_cpu_to_be_16(flow_id);
    sld_h_ack->flags = rte_cpu_to_be_16(FLAG_ACK);
    sld_h_ack->timestamp = 0;

    printf("[DEBUG SERVER] Sending ACK: flow_id=%u, ack_num=%u, flags=0x%x\n", 
           flow_id, ack_num, FLAG_ACK);

    ack->l2_len = RTE_ETHER_HDR_LEN;
    ack->l3_len = sizeof(struct rte_ipv4_hdr);
    ack->data_len = header_size + ack_len;
    ack->pkt_len = header_size + ack_len;
    ack->nb_segs = 1;

    int nb_tx = rte_eth_tx_burst(port, 0, &ack, 1);
    if (nb_tx < 1) {
        printf("[DEBUG SERVER] Failed to send ACK via tx_burst\n");
        rte_pktmbuf_free(ack);
        return -1;
    }

    printf("[DEBUG SERVER] ACK sent successfully via port %u\n", port);
    return 0;
}

/* lcore main function */
static __rte_noreturn void lcore_main(void) {
    uint16_t port = 1;
    uint16_t nb_rx;

    // Initialize flow states
    for (int i = 0; i < MAX_FLOWS; i++) {
        flow_states[i].expected_seq = 0;
        flow_states[i].packets_received = 0;
        flow_states[i].packets_acked = 0;
        flow_states[i].bytes_received = 0;
        flow_states[i].active = false;
    }

    printf("\nCore %u receiving packets. [Ctrl+C to quit]\n", rte_lcore_id());

    uint64_t last_print = 0;
    uint64_t start_time = 0;
    bool started = false;

    for (;;) {
        struct rte_mbuf *bufs[BURST_SIZE];
        nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        if (!started) {
            start_time = rte_get_timer_cycles();
            started = true;
        }

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *pkt = bufs[i];
            uint16_t flow_id;
            uint32_t seq_num;
            uint16_t flags;
            uint32_t data_len;

            if (parse_data_packet(pkt, &flow_id, &seq_num, &flags, &data_len) < 0) {
                rte_pktmbuf_free(pkt);
                continue;
            }

            if (flow_id >= MAX_FLOWS) {
                rte_pktmbuf_free(pkt);
                continue;
            }

            struct flow_recv_state *fs = &flow_states[flow_id];

            if (!fs->active) {
                fs->active = true;
                fs->expected_seq = 0;
                printf("Flow %u activated\n", flow_id);
            }

            if (flags & FLAG_DATA) {
                if (seq_num == fs->expected_seq) {
                    // In-order packet
                    fs->expected_seq = seq_num + 1;
                    fs->packets_received++;
                    fs->bytes_received += data_len;
                    
                    // Send ACK
                    send_ack(port, pkt, flow_id, fs->expected_seq);
                    fs->packets_acked++;
                } else if (seq_num < fs->expected_seq) {
                    // Duplicate packet -> send duplicate ACK
					printf("[DEBUG] Send duplicate ACK");
                    send_ack(port, pkt, flow_id, fs->expected_seq);
                    fs->packets_acked++;
                } else {
                    // Out of order packet -> send current expected ACK
					printf("[DEBUG] Send out of order ACK");
                    send_ack(port, pkt, flow_id, fs->expected_seq);
                    fs->packets_acked++;
                }
            }

            rte_pktmbuf_free(pkt);
        }

        // Print statistics every second
        uint64_t now = rte_get_timer_cycles();
        if (now - last_print > rte_get_timer_hz()) {
            bool any_active = false;
            for (int f = 0; f < MAX_FLOWS; f++) {
                if (flow_states[f].active && flow_states[f].packets_received > 0) {
                    any_active = true;
                    break;
                }
            }

            if (any_active) {
                printf("\n=== Statistics ===\n");
                double elapsed = (double)(now - start_time) / rte_get_timer_hz();
                
                for (int f = 0; f < MAX_FLOWS; f++) {
                    if (flow_states[f].active) {
                        double throughput_mbps = (flow_states[f].bytes_received * 8.0) / 
                                                 (elapsed * 1e6);
                        printf("Flow %d: Received %u packets (%lu bytes), "
                               "Sent %u ACKs, Throughput: %.2f Mbps\n",
                               f, flow_states[f].packets_received,
                               flow_states[f].bytes_received,
                               flow_states[f].packets_acked,
                               throughput_mbps);
                    }
                }
            }
            
            last_print = now;
        }
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
	// struct rte_mempool *mbuf_pool;
	unsigned nb_ports = 1;
	uint16_t portid;
	
	/* Initializion the Environment Abstraction Layer (EAL) */

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Allocates mempool to hold the mbufs */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
										MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports */
	RTE_ETH_FOREACH_DEV(portid)
	if (portid == 1 && port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
				 portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore */
	lcore_main();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_common.h>
#include <time.h>

// #define PKT_TX_IPV4          (1ULL << 55)
// #define PKT_TX_IP_CKSUM      (1ULL << 54)

#define RX_RING_SIZE 8192
#define TX_RING_SIZE 8192

#define NUM_MBUFS 65536
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 128

#define TIMEOUT_US 200000
#define MAX_RETRIES 10
#define BASE_TIMEOUT_US 50000   // 50ms base
#define MAX_TIMEOUT_US 500000  

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

/* Window entry for tracking sent packets */
struct window_entry {
    uint32_t seq_num;
    struct rte_mbuf *pkt;
    uint64_t send_time;
    bool acked;
    uint8_t retries;
};

/* Per-flow state */
struct flow_state {
    uint32_t send_base;           // Oldest unacked packet
    uint32_t next_seq_num;        // Next sequence number
    struct window_entry *window;
    uint16_t window_start;
    uint16_t window_count;
    bool connected;
    uint32_t packets_sent;
    uint32_t packets_acked;
    uint32_t total_packets;
    uint64_t start_time;
    uint64_t end_time;
};

/* Define the mempool globally */
struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_eth;
static size_t message_size = 1000;
static uint32_t seconds = 1;

size_t window_len = 512;

long flow_size = 10000;
int packet_len = 1400;
int flow_num = 1;

/* Flow states */
struct flow_state *flow_states = NULL;

static uint64_t raw_time(void) {
    struct timespec tstart={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    uint64_t t = (uint64_t)(tstart.tv_sec*1.0e9 + tstart.tv_nsec);
    return t;

}

static uint64_t time_now(uint64_t offset) {
    return raw_time() - offset;
}

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

/* Function to parse ACK packets
 * Parameters:
 *   pkt: The received packet to parse
 *   flow_id: Pointer to store the extracted flow ID
 *   ack_num: Pointer to store the extracted acknowledgment number
 *   flags: Pointer to store the extracted flags
 * Returns:
 *   0 on success, -1 on failure (e.g., invalid packet)
 */
static int parse_ack_packet(struct rte_mbuf *pkt, uint16_t *flow_id, 
                            uint32_t *ack_num, uint16_t *flags) {
    uint8_t *p = rte_pktmbuf_mtod(pkt, uint8_t *);
    
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(p);
    p += sizeof(*eth_hdr);
    
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
    
    if (ip_hdr->next_proto_id != IPPROTO_UDP) {
        return -1;
    }

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(p);
    p += sizeof(*udp_hdr);

    struct sliding_hdr *sld_hdr = (struct sliding_hdr *)(p);
    
    *flow_id = rte_be_to_cpu_16(sld_hdr->flow_id);
    *ack_num = rte_be_to_cpu_32(sld_hdr->ack_num);
    *flags = rte_be_to_cpu_16(sld_hdr->flags);

    return 0;
}

/* Function to process received ACK packets
 * Parameters:
 *   fs: Pointer to the flow state structure
 *   ack_num: The acknowledgment number from the received ACK packet
 * This function updates the sliding window based on the received ACK number,
 * freeing acknowledged packets and sliding the window forward.
 */
static void process_ack(struct flow_state *fs, uint32_t ack_num) {
    while (fs->window_count > 0) {
        uint16_t idx = fs->window_start;
        struct window_entry *entry = &fs->window[idx];

        if (entry->seq_num < ack_num) {
            // Packet acknowledged
            if (entry->pkt) {
                rte_pktmbuf_free(entry->pkt);
                entry->pkt = NULL;
            }
            entry->acked = true;
            
            // Slide window
            fs->window_start = (fs->window_start + 1) % window_len;
            fs->window_count--;
            fs->send_base = ack_num;
            fs->packets_acked++;
        } else {
            break;
        }
    }
}

static void check_timeouts(uint16_t port, struct flow_state *fs, uint16_t flow_id) {
    uint64_t now = rte_get_timer_cycles();

    for (uint16_t i = 0; i < fs->window_count; i++) {
        uint16_t idx = (fs->window_start + i) % window_len;
        struct window_entry *entry = &fs->window[idx];

        // Exponential backoff: 50ms, 100ms, 200ms, 400ms, 500ms
        uint64_t timeout_us = BASE_TIMEOUT_US * (1 << entry->retries);
        if (timeout_us > MAX_TIMEOUT_US) timeout_us = MAX_TIMEOUT_US;
        
        uint64_t timeout_cycles = (timeout_us * rte_get_timer_hz()) / 1000000;

        if (!entry->acked && (now - entry->send_time) > timeout_cycles) {
            if (entry->retries >= MAX_RETRIES) {
                continue;
            }

            printf("[TIMEOUT] Flow %u, seq %u, retry %u\n", flow_id, entry->seq_num, entry->retries);

            // Retransmit the packet
            if (entry->pkt) {
                struct rte_mbuf *dup_pkt = rte_pktmbuf_clone(entry->pkt, mbuf_pool);
                if (dup_pkt) {
                    uint16_t nb_tx = rte_eth_tx_burst(port, 0, &dup_pkt, 1);
                    if (nb_tx < 1) {
                        rte_pktmbuf_free(dup_pkt);
                    }
                }
            }

            entry->send_time = now;
            entry->retries++;
        }
    }
}

/* Function to send a data packet
 * Parameters:
 *   port: The port to send the packet on
 *   flow_id: The flow ID for the packet
 *   fs: Pointer to the flow state structure
 *   data: Pointer to the payload data
 *   data_len: Length of the payload data
 * Returns:
 *   0 on success, -1 on failure (e.g., memory allocation failure)
 */
static int send_data_packet(uint16_t port, uint16_t flow_id, 
                            struct flow_state *fs, const char *data, uint32_t data_len) {
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
    if (pkt == NULL) {
        return -1;
    }

    size_t header_size = 0;
    uint8_t *ptr = rte_pktmbuf_mtod(pkt, uint8_t *);

    // Specify the dst mac address
    struct rte_ether_addr dst = {{0x14, 0x58, 0xd0, 0x58, 0x8f, 0xa3}};

    /* Ethernet header */
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)ptr;
    rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
    rte_ether_addr_copy(&dst, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
    ptr += sizeof(*eth_hdr);
    header_size += sizeof(*eth_hdr);

    /* IPv4 header */
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)ptr;
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0x0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + 
                                               sizeof(struct rte_udp_hdr) + 
                                               sizeof(struct sliding_hdr) + data_len);
    ipv4_hdr->packet_id = rte_cpu_to_be_16(1);
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 10));
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 20));

    uint32_t ipv4_checksum = wrapsum(checksum((unsigned char *)ipv4_hdr, 
                                      sizeof(struct rte_ipv4_hdr), 0));
    ipv4_hdr->hdr_checksum = rte_cpu_to_be_32(ipv4_checksum);
    header_size += sizeof(*ipv4_hdr);
    ptr += sizeof(*ipv4_hdr);

    /* UDP header */
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)ptr;
    uint16_t src_port = 5001 + flow_id;
    uint16_t dst_port = 5001 + flow_id;
    udp_hdr->src_port = rte_cpu_to_be_16(src_port);
    udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
    udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + 
                                          sizeof(struct sliding_hdr) + data_len);
    udp_hdr->dgram_cksum = 0;
    ptr += sizeof(*udp_hdr);
    header_size += sizeof(*udp_hdr);

    /* Sliding window header */
    struct sliding_hdr *sld_hdr = (struct sliding_hdr *)ptr;
    sld_hdr->seq_num = rte_cpu_to_be_32(fs->next_seq_num);
    sld_hdr->ack_num = 0;
    sld_hdr->flow_id = rte_cpu_to_be_16(flow_id);
    sld_hdr->flags = rte_cpu_to_be_16(FLAG_DATA);
    sld_hdr->timestamp = rte_cpu_to_be_64(raw_time());
    ptr += sizeof(*sld_hdr);
    header_size += sizeof(*sld_hdr);

    /* Payload */
    if (data && data_len > 0) {
        memcpy(ptr, data, data_len);
    }

    pkt->l2_len = RTE_ETHER_HDR_LEN;
    pkt->l3_len = sizeof(struct rte_ipv4_hdr);
    pkt->data_len = header_size + data_len;
    pkt->pkt_len = header_size + data_len;
    pkt->nb_segs = 1;

    // Clone for retransmission
    struct rte_mbuf *clone_pkt = rte_pktmbuf_clone(pkt, mbuf_pool);

    int nb_tx = rte_eth_tx_burst(port, 0, &pkt, 1);
    if (nb_tx < 1) {
        rte_pktmbuf_free(pkt);
        if (clone_pkt)
            rte_pktmbuf_free(clone_pkt);
        return -1;
    }

    // Add to window
    uint16_t idx = (fs->window_start + fs->window_count) % window_len;
    fs->window[idx].seq_num = fs->next_seq_num;
    fs->window[idx].pkt = clone_pkt;
    fs->window[idx].send_time = rte_get_timer_cycles();
    fs->window[idx].acked = false;
    fs->window[idx].retries = 0;
    fs->window_count++;

    fs->next_seq_num++;
    fs->packets_sent++;

    return 0;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
    struct rte_eth_link link;

	if (!rte_eth_dev_is_valid_port(port)) {
        printf("ERROR: Port %u is not valid!\n", port);
		return -1;
    }

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0)
	{
		printf("Error during getting device (port %u) info: %s\n",
			   port, strerror(-retval));
		return retval;
	}

    printf("Port %u info: driver=%s\n", port, dev_info.driver_name);

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

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

	/* Starting Ethernet port */
	retval = rte_eth_dev_start(port);
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

    // Check link status
    retval = rte_eth_link_get_nowait(port, &link);
    if (retval < 0) {
        printf("ERROR: Failed to get link status for port %u\n", port);
        return retval;
    }

    if (link.link_status == RTE_ETH_LINK_UP) {
        printf("Port %u: Link UP - speed %u Mbps - %s\n",
               port, link.link_speed,
               (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
               "full-duplex" : "half-duplex");
    } else {
        printf("WARNING: Port %u: Link DOWN!\n", port);
        printf("Check if cable is connected or port is enabled\n");
    }

	return 0;
}

/*lcore function*/
static __rte_noreturn void lcore_main() {
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t port = 1;
    
    // Initialize flow states
    flow_states = calloc(flow_num, sizeof(struct flow_state));
    if (!flow_states) {
        rte_exit(EXIT_FAILURE, "Cannot allocate flow states\n");
    }

    // Allocate window for each flow
    for (int i = 0; i < flow_num; i++) {
        flow_states[i].window = calloc(window_len, sizeof(struct window_entry));
        if (!flow_states[i].window) {
            rte_exit(EXIT_FAILURE, "Cannot allocate window for flow %d\n", i);
        }
    }

    // Calculate total packets per flow
    uint32_t total_packets_per_flow = (flow_size + packet_len - 1) / packet_len;
    
    for (int i = 0; i < flow_num; i++) {
        flow_states[i].send_base = 0;
        flow_states[i].next_seq_num = 0;
        flow_states[i].window_start = 0;
        flow_states[i].window_count = 0;
        flow_states[i].connected = true;
        flow_states[i].packets_sent = 0;
        flow_states[i].packets_acked = 0;
        flow_states[i].total_packets = total_packets_per_flow;
        flow_states[i].start_time = 0;
        flow_states[i].end_time = 0;
    }

    printf("Starting transmission: %d flows, %ld bytes per flow, %d bytes per packet\n",
           flow_num, flow_size, packet_len);
    printf("Total packets per flow: %u, Window size: %zu\n", total_packets_per_flow, window_len);

    // Check link status before starting
    struct rte_eth_link link;
    int link_ret = rte_eth_link_get_nowait(port, &link);
    if (link_ret == 0) {
        if (link.link_status == RTE_ETH_LINK_UP) {
            printf("[INFO] Port %u link is UP - speed %u Mbps\n", port, link.link_speed);
        } else {
            printf("[ERROR] Port %u link is DOWN! Cannot transmit.\n", port);
            rte_exit(EXIT_FAILURE, "Link is down\n");
        }
    }

    uint64_t start_time = raw_time();
    
    // Prepare payload
    char *payload = malloc(packet_len);
    if (!payload) {
        rte_exit(EXIT_FAILURE, "Cannot allocate payload\n");
    }
    memset(payload, 'A', packet_len);

    bool all_done = false;
    uint32_t current_flow = 0;
    uint64_t last_print = raw_time();
    uint32_t last_total_sent = 0;

    while (!all_done) {
        all_done = true;

        // AGGRESSIVE SENDING: Fill all windows before processing ACKs
        for (int send_round = 0; send_round < 100; send_round++) {  // Increased from 1
            bool sent_anything = false;
            
            for (int f = 0; f < flow_num; f++) {
                current_flow = (current_flow + 1) % flow_num;
                struct flow_state *fs = &flow_states[current_flow];

                // Check if this flow is done
                if (fs->packets_sent >= fs->total_packets) {
                    if (fs->window_count == 0 && fs->end_time == 0) {
                        fs->end_time = raw_time();
                    }
                    continue;
                }

                all_done = false;

                // Record start time for first packet
                if (fs->packets_sent == 0) {
                    fs->start_time = raw_time();
                }

                // Send packets aggressively to fill window
                while (fs->window_count < window_len && 
                       fs->packets_sent < fs->total_packets) {
                    
                    uint32_t remaining_bytes = flow_size - (fs->packets_sent * packet_len);
                    uint32_t send_len = (remaining_bytes < packet_len) ? remaining_bytes : packet_len;
                    
                    if (send_data_packet(port, current_flow, fs, payload, send_len) < 0) {
                        break;
                    }
                    sent_anything = true;
                }
            }
            
            // If no flow could send, break early
            if (!sent_anything) break;
        }

        // BATCH PROCESS ACKs (process multiple bursts)
        for (int ack_round = 0; ack_round < 10; ack_round++) {
            uint16_t nb_rx = rte_eth_rx_burst(port, 0, pkts, BURST_SIZE);
            
            if (nb_rx == 0) break;

            for (uint16_t i = 0; i < nb_rx; i++) {
                uint16_t flow_id;
                uint32_t ack_num;
                uint16_t flags;
                
                if (parse_ack_packet(pkts[i], &flow_id, &ack_num, &flags) == 0) {
                    if (flow_id < flow_num && (flags & FLAG_ACK)) {
                        process_ack(&flow_states[flow_id], ack_num);
                    } 
                }
                rte_pktmbuf_free(pkts[i]);
            }
        }

        // Check timeouts (but not too frequently)
        static uint64_t last_timeout_check = 0;
        uint64_t now_cycles = rte_get_timer_cycles();
        if (now_cycles - last_timeout_check > rte_get_timer_hz() / 100) {  // Check every 10ms
            for (int f = 0; f < flow_num; f++) {
                if (flow_states[f].packets_sent < flow_states[f].total_packets ||
                    flow_states[f].window_count > 0) {
                    check_timeouts(port, &flow_states[f], f);
                }
            }
            last_timeout_check = now_cycles;
        }

    }

    printf("\nAll packets sent. Waiting for final ACKs...\n");
    
    for (int wait_round = 0; wait_round < 1000; wait_round++) {
        bool all_acked = true;
        
        // Process remaining ACKs
        for (int ack_round = 0; ack_round < 10; ack_round++) {
            uint16_t nb_rx = rte_eth_rx_burst(port, 0, pkts, BURST_SIZE);
            
            if (nb_rx == 0) break;

            for (uint16_t i = 0; i < nb_rx; i++) {
                uint16_t flow_id;
                uint32_t ack_num;
                uint16_t flags;
                
                if (parse_ack_packet(pkts[i], &flow_id, &ack_num, &flags) == 0) {
                    if (flow_id < flow_num && (flags & FLAG_ACK)) {
                        process_ack(&flow_states[flow_id], ack_num);
                    }
                }
                rte_pktmbuf_free(pkts[i]);
            }
        }
        
        // Check if all flows have no outstanding packets
        for (int f = 0; f < flow_num; f++) {
            if (flow_states[f].window_count > 0) {
                all_acked = false;
            } else if (flow_states[f].end_time == 0) {
                flow_states[f].end_time = raw_time();
            }
        }
        
        // Retransmit any timed-out packets
        for (int f = 0; f < flow_num; f++) {
            if (flow_states[f].window_count > 0) {
                check_timeouts(port, &flow_states[f], f);
            }
        }
        
        if (all_acked) {
            printf("All ACKs received!\n");
            break;
        }
        
        rte_delay_us_block(1000);  // Wait 1ms between checks
    }
    
    // Ensure all end times are set
    for (int f = 0; f < flow_num; f++) {
        if (flow_states[f].end_time == 0) {
            flow_states[f].end_time = raw_time();
        }
    }

    uint64_t end_time = raw_time();
    double total_time_sec = (end_time - start_time) / 1e9;

    // Get final port statistics
    struct rte_eth_stats final_stats;
    rte_eth_stats_get(port, &final_stats);
    
    printf("\n=== Port Statistics ===\n");
    printf("TX packets: %lu\n", final_stats.opackets);
    printf("RX packets: %lu\n", final_stats.ipackets);
    printf("TX errors: %lu\n", final_stats.oerrors);
    printf("RX errors: %lu\n", final_stats.ierrors);
    printf("RX missed: %lu\n", final_stats.imissed);
    printf("RX no mbuf: %lu\n", final_stats.rx_nombuf);

    printf("\n=== Results ===\n");
    printf("Total time: %.3f seconds\n", total_time_sec);
    
    for (int f = 0; f < flow_num; f++) {
        double flow_time = (flow_states[f].end_time - flow_states[f].start_time) / 1e9;
        double throughput_mbps = (flow_size * 8.0) / (flow_time * 1e6);
        double avg_latency_ms = flow_time * 1000.0 / flow_states[f].total_packets;
        
        printf("\nFlow %d:\n", f);
        printf("  Packets sent: %u\n", flow_states[f].packets_sent);
        printf("  Packets acked: %u\n", flow_states[f].packets_acked);
        printf("  Flow time: %.3f seconds\n", flow_time);
        printf("  Throughput: %.2f Mbps\n", throughput_mbps);
        printf("  Average latency: %.3f ms\n", avg_latency_ms);
    }

    if (flow_num > 1) {
        double total_throughput = 0;
        for (int f = 0; f < flow_num; f++) {
            double flow_time = (flow_states[f].end_time - flow_states[f].start_time) / 1e9;
            total_throughput += (flow_size * 8.0) / (flow_time * 1e6);
        }
        printf("\nAggregate throughput: %.2f Mbps\n", total_throughput);
        printf("Average per-flow throughput: %.2f Mbps\n", total_throughput / flow_num);
    }

    // Cleanup
    for (int f = 0; f < flow_num; f++) {
        for (int i = 0; i < window_len; i++) {
            if (flow_states[f].window[i].pkt) {
                rte_pktmbuf_free(flow_states[f].window[i].pkt);
            }
        }
        free(flow_states[f].window);
    }
    free(flow_states);
    free(payload);

    rte_exit(EXIT_SUCCESS, "Done\n");
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */

int main(int argc, char *argv[])
{

	unsigned nb_ports;
	uint16_t portid;

    if (argc == 3) {
        flow_num = (int) atoi(argv[1]);
        flow_size = atol(argv[2]);
    } else {
        printf( "usage: ./lab1-client <flow_num> <flow_size>\n");
        return 1;
    }


	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Allocates mempool to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
										MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports.*/
	RTE_ETH_FOREACH_DEV(portid)
	if (portid == 1 && port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. */
	lcore_main();

    printf("Done!\n");
	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

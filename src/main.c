/** 
 * arptool
 * 
 * Will capture arp packets on the network and build a mapping of macs to ip addresses. used for research purposes only.
 * 
 * @author r3v
 * @date July 28th, 2024
 */

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const struct pcap_pkthdr* header) { 
	printf("caplen:%-4d|Totlen:%-4d|\n", header->caplen,header->len);
	return;
}

void packet_handler(
	u_char *args, 
	const struct pcap_pkthdr* header, 
	const u_char* packet
) { 
	// Determine packet type 
	struct ether_header *eth_header; 

	// Hardcody when it comes to adding the padding
	eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) { 
		printf("|IPV4  |");
	} else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) { 
		printf("|ARP   |");
	} else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) { 
		printf("|RARP  |"); // Obsolete protocol according to google
	} else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) { 
		printf("|IPV6  |");
	} else {
		printf("|0x%x|", ntohs(eth_header->ether_type));
	}

	// Print length information
	print_packet_info(header);
	return;
}

int main() { 
	char *devname; // name of the device
	char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
	pcap_if_t *all_devs; // arra

	/* Find a device */
	// Can simple grab default capture device with pcap_lookupdev();
	if (pcap_findalldevs(&all_devs, errbuf) < 0) { 
		fprintf(stderr, "Error trying to find devices");
		return 1;
	}

	devname = all_devs->name; // Grab the default capture device
	
	/* Print all devices */
	printf("Devices found\n------------------------\n");
	while (all_devs != NULL) { 
		printf("** %s\n", all_devs->name);
		all_devs = all_devs->next;	
	}
	putc('\n', stdout);

	/* Get device info */
	printf("Getting device info for default cap dev %s\n", devname);

	char ip[13];
	char subnet_mask[13];
	bpf_u_int32 ip_raw; // Ip address as integer
	bpf_u_int32 subnet_mask_raw; // Subnet mask as integer
	struct in_addr address; // used for both ip and subnet

	int lookup_return_code = pcap_lookupnet(
		devname, 
		&ip_raw, 
		&subnet_mask_raw,
		errbuf
	);

	if (lookup_return_code < 0) { 
		printf("%s\n", errbuf);
		return 1;
	}

	// Get ip address in human readable form 
	address.s_addr = ip_raw;
	strcpy(ip, inet_ntoa(address));
	if (ip == NULL) { 
		perror("inet_ntoa error");
		return 1;
	}

	// get subnet mask in human readable form 
	address.s_addr = subnet_mask_raw;
	strcpy(subnet_mask, inet_ntoa(address));
	if (subnet_mask == NULL) { 
		perror("inet_ntoa");
		return 1;
	}

	printf("Device: %s\n", devname);
	printf("Ip address: %s\n", ip);
	printf("Subnet mask: %s\n", subnet_mask);

	/* Open the device for live capture */	
	pcap_t *handle;
	int snapshot_len = 1028;
	int promiscious = 0;
	int timeout_limit = 100; // milliseconds (using delay wireshark uses)

	printf("Going to capture...\n");

	handle = pcap_open_live(
		devname, 
		snapshot_len,
		promiscious,
		timeout_limit, 
		errbuf
	);
	if (handle == NULL) { 
		printf("Unable to open %s\n", devname);
		return 2;
	}

	/* Capture packets in a loop and print information */
	pcap_loop(handle, 0, packet_handler, NULL);
	pcap_close(handle);

	return 0;
}

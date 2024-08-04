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
	struct pcap_pkthdr packet_header;
	const u_char *packet; 
	int packet_count_limit = 1; // Number of packets to capture
	int timeout_limit = 10000; // milliseconds

	printf("Going to capture...\n");

	handle = pcap_open_live(
		devname, 
		BUFSIZ,
		packet_count_limit,
		timeout_limit, 
		errbuf
	);
	if (handle == NULL) { 
		printf("Unable to open %s\n", devname);
		return 2;
	}

	/* Capture a packet */
	packet = pcap_next(handle, &packet_header);
	if (packet == NULL) { 
		printf("Unable to capture a packet\n");
		return 2;
	}

	/* Print packet info */
	printf("Packet capture length: %d\n", packet_header.caplen);
	printf("Packet total length: %d\n", packet_header.len);

	return 0;
}

#include <stdio.h>
#include <pcap.h>
#include <winsock.h>

#define SYN 0x02
#define ACK 0x10

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Process the packet here
    const u_char *data = packet;
    int size = header->caplen;
    int src_port, dst_port;
    unsigned char flags;

    // Parse the TCP header
    data += 14 + 20;
    src_port = (data[0] << 8) + data[1];
    dst_port = (data[2] << 8) + data[3];
    flags = data[13];

    // Check for a SYN packet to an open port
    if ((flags & SYN) && !(flags & ACK)) {
        printf("Potential port scan detected: source port %d, destination port %d\n", src_port, dst_port);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // Get the default network interface
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // Open the network interface in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Get the network interface information
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, process_packet, NULL);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

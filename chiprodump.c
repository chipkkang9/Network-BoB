#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#define BUFFSIZE 1024


typedef struct radiotap_header {
	unsigned char it_version;
	unsigned char it_pad;
	unsigned char it_len[2];
	unsigned char it_present1[16];
}RT_header;

u_int8_t is_it_beacon;
u_int8_t how_long_SS;

typedef struct SSID_Frame {
	unsigned char BSS_ID[6];
	unsigned char ESS_ID[24];
}SSID;


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int check_Len(const u_char* packet){
	RT_header* rt;
	rt = (RT_header *)packet;
	if((rt->it_len[0] = packet[2]) == 24) {
		is_it_beacon = packet[24];
		return 0;
	}
	return 1;	
}

void GetBssid2(SSID* ssid_block, const u_char* packet, int n) {

	int flag[6] = {0,};

	if(n == 0)	{

		for(int i = 0; i < 6; i++){
			(ssid_block + n)->BSS_ID[i] = packet[40+i];
		}
	}
	
	else	{

		
			
		for(int j = 0; j < 6; j++)
			flag[j] = 1;

		for(int j = 0; j < 6; j++)	{

			if(packet[40+j] == (ssid_block + n)->BSS_ID[j])	{
				
				flag[j] = 0;
			}
			
		}
			
		

	if((flag[0] != 0) || (flag[1] != 0) || (flag[2] != 0) || (flag[3] != 0) || (flag[4] != 0) || (flag[5] != 0))	{

		for(int i = 0; i < 6; i++)	{

			(ssid_block + n)->BSS_ID[i] = packet[40+i];
			
		}
		}
	}
}

void PrintSSID(SSID* ssid_block, char* str, int n)	{
	for(int j = 0; j < 6; j++)	{
		if(j != 5) printf("%02X:", (ssid_block + n)->BSS_ID[j]);
		else {
			printf("%02X\t\t\t", (ssid_block + n)->BSS_ID[j]);
			puts(str);
		}
		
	}
	
}

char* GetEssid(SSID* ssid_block, const u_char* packet, char* tmp, int n)	{
	
	char str[100];
	how_long_SS = packet[61];
	for(int i = 0; i < how_long_SS; i++)	{
		str[0] = '\0';
		(ssid_block + n)->ESS_ID[i] = packet[62 + i];
		sprintf(str, "%c", (ssid_block + n)->ESS_ID[i]);

		strcat(tmp, str);
	}

	return tmp;

}

void GetBssid(SSID* ssid_block, const u_char* packet, int n)	{

	for(int i = 0; i < 6; i++)	{

		(ssid_block + n)->BSS_ID[i] = packet[40 + i];

	}

}

int main(int argc, char* argv[]) {
	// exception of no network
	if(argc != 2){
		usage();
		return false;
	}
	
	char errbuf[PCAP_ERRBUF_SIZE]; // in pcap.h the size of PCAP_ERRBUF_SIZE is defined 256
	struct pcap_pkthdr* header;
	const u_char* packet;
	char* network = argv[1]; // network name what we brought
	pcap_t* pcap = pcap_open_live(network, BUFFSIZE, 1, 1000, errbuf);
	int loop = 0;
	SSID* ssid_block = (SSID*)malloc((loop+1) * sizeof(SSID) * 5);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", network, errbuf);
		return -1;
	}

	printf("BSSID\t\t\t\t\tESSID\n");

	while(true){
		char ESSID[100] = {0,};
		ssid_block = (SSID*)realloc(ssid_block, sizeof(SSID) * (loop + 1) * 5);
		int res = pcap_next_ex(pcap, &header, &packet);
				
		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		if ((check_Len(packet) == 0) && (is_it_beacon == 128))	{
			GetBssid(ssid_block, packet, loop);
			GetEssid(ssid_block, packet, ESSID, loop);
			PrintSSID(ssid_block, ESSID, loop);
		}

		loop++;

	}
	free(ssid_block);
	pcap_close(pcap);
	return 0;
}

#ifndef ARIP_UDP_h
#define ARIP_UDP_h

//pseudo header for checksum calculation
struct fakehdr{
	unsigned long ip_src;
	unsigned long ip_dst;
	unsigned char pad;
	unsigned char ip_p;
	unsigned short udp_len;
};

//UDP header
struct udphdr {
	unsigned int udp_src;//source port
	unsigned int udp_dst;//destination port
	unsigned int udp_len;//packet Length
	unsigned int udp_sum;//checksum
};

//UDP packet
class UDPpacket
{
	public:
		UDPpacket();
		void init();
		void setpacket(unsigned char *p);
		void setfake(unsigned long _ip_src,unsigned long _ip_dst);
		void setport(unsigned int _udp_src,unsigned int _udp_dst);
		int checksum();
		unsigned char* get_payload_s();
		unsigned char* getudphdr();
		unsigned int getlen();
		unsigned int getdstport();
		void setlen(unsigned int len);
		int set_payload(unsigned int len,unsigned char *data);
	private:
		unsigned char *packet;
		struct fakehdr fake;
		struct udphdr *h_udp;
};
#endif

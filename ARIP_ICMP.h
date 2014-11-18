#ifndef ARIP_ICMP_h
#define ARIP_ICMP_h

//ICMP header for echo & reply
struct icmp_erhdr{
	unsigned char type;
	unsigned char code;
	unsigned short chksum;
	unsigned short id;
	unsigned short snumber;
};

//ICMP packet
class ICMPpacket
{
	public:
		ICMPpacket();
		void init();
		void setpacket(unsigned char *p);
		void setlen(unsigned int len);
		int checksum();
		unsigned char gettype();
		void settype(unsigned char _type);
		unsigned char getcode();
		void setcode(unsigned char _code);
		unsigned short getid();
		void setid(unsigned short _id);
		unsigned short getsnumber();
		void setsnumber(unsigned short _snumber);
		unsigned char* get_payload_s();
		unsigned char* get_payload_er_s();
		unsigned char* geticmphdr();
		int set_payload_er(unsigned int len,unsigned char *data);
		int set_payload(unsigned int len,unsigned char *data);
	private:
		unsigned char *packet;
		unsigned int length;
		struct icmp_erhdr *h_icmp;
};
#endif

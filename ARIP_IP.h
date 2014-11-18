#ifndef ARIP_IP_h
#define ARIP_IP_h

//IP header
struct iphdr {
	unsigned char ip_vhl;	/* version << 4 | header length >> 2 */
	unsigned char ip_tos;	/* type of service */
	unsigned short ip_len;	/* total length */
	unsigned short ip_id;	/* identification */
	unsigned short ip_off;	/* fragment offset field */
	#define IP_RF 0x8000        /* reserved fragment flag */
	#define IP_DF 0x4000        /* dont fragment flag */
	#define IP_MF 0x2000        /* more fragments flag */
	#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	unsigned char ip_ttl;	/* time to live */
	unsigned char ip_p;	/* protocol */
	unsigned short ip_sum;	/* checksum */
	unsigned long ip_src;
	unsigned long ip_dst;	/* source and dest address */
};

//IP packet
class IPpacket
{
	public:
		IPpacket();
		void init();
		void setpacket(unsigned char *p);
		int checksum();
		void setdefaulthdr();
		void setproto(unsigned char proto);
		void setaddr(unsigned long src_addr,unsigned long dst_addr);
		void setlen(unsigned int len);
		unsigned char* getiphdr();
		unsigned char* get_payload_s();
		unsigned int get_total_len();
		unsigned int get_hdr_len();
	private:
		unsigned char *packet;
		struct iphdr *h_ip;
} ;
#endif

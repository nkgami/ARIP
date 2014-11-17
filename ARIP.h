#ifndef ARIP_h
#define ARIP_h

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

struct fakehdr{
	unsigned long ip_src;
	unsigned long ip_dst;
	unsigned char pad;
	unsigned char ip_p;
	unsigned short udp_len;
};

struct udphdr {
	unsigned int udp_src;//source port
	unsigned int udp_dst;//destination port
	unsigned int udp_len;//packet Length
	unsigned int udp_sum;//checksum
};

struct icmp_erhdr{
	unsigned char type;
	unsigned char code;
	unsigned short chksum;
	unsigned short id;
	unsigned short snumber;
};

class SNMPpacket
{
	public:
		SNMPpacket();
		void setpacket(unsigned char *p);
		unsigned char get_length();
		unsigned char get_version();
		unsigned char *get_comname_p();
		unsigned char get_comname_len();
		unsigned char get_pdu_type();
		unsigned char get_pdu_len();
		unsigned char get_reqid_type();
		unsigned char get_reqid_len();
		unsigned char *get_reqid_p();
		unsigned char get_errst();
		unsigned char get_errin();
		unsigned char get_varib_type();
		unsigned char get_varib_len();
		unsigned char *get_varib_p();
		unsigned char get_value_type();
		unsigned char get_value_len();
		unsigned char *get_value_p();
		void set_length(unsigned char c);
		void set_pdu_type(unsigned char c);
		void set_pdu_len(unsigned char c);
		void set_errst(unsigned char c);
		void set_errin(unsigned char c);
		void set_value(unsigned char type,unsigned char len,unsigned char *data);
	private:
		unsigned char *packet;
		unsigned char length;
};

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

// クラスの定義
// クラス名・コンストラクタ名・関数名や使用する変数名を定義します。
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
} ;

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

class Frame
{
	public:
		Frame();
		void init();
		void setframe(unsigned char *p);
		void set_total_len(unsigned int len);
		void set_payload_len(unsigned int len);
		void sethdr(int type,int next);
		unsigned char* getiphdr();
		unsigned int getfrlen_nocrc();
		unsigned int getfrlen_withcrc();
		int checkcrc();
		void setcrc();
	private:
		unsigned char *h_frame;
		unsigned int p_length;
		unsigned int t_length;
		unsigned int hdr_length;
};

class Net_util
{
  public:
    Net_util();
    unsigned long ntohl(unsigned long source);
    unsigned int ntohs(unsigned int source);
};
#endif

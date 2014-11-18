#ifndef ARIP_IP485_h
#define ARIP_IP485_h

//Frame on RS485
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
#endif

#ifndef ARIP_SNMP_h
#define ARIP_SNMP_h

//SNMP packet
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
#endif

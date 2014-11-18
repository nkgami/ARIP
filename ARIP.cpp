#include <Arduino.h>
#include "ARIP.h"
#include "utils.h"

SNMPpacket::SNMPpacket()
{
	packet = NULL;
	length = 0;
}

void SNMPpacket::setpacket(unsigned char *p){
	packet = p;
}

unsigned char SNMPpacket::get_length(){
	length = packet[1] + 2;
	return length;
}

void SNMPpacket::set_length(unsigned char c){
	length = c;
	packet[1] = c;
}

unsigned char SNMPpacket::get_version(){
	return (unsigned char)(packet[4]);
}

unsigned char* SNMPpacket::get_comname_p(){
	return packet+7;
}

unsigned char SNMPpacket::get_comname_len(){
	return (unsigned char)(packet[6]);
}

unsigned char SNMPpacket::get_pdu_type(){
	unsigned int point;
	point = 7 + (unsigned int)packet[6];
	return (unsigned char)(packet[point]);
}

void SNMPpacket::set_pdu_type(unsigned char c){
	unsigned int point;
	point = 7 + (unsigned int)packet[6];
	packet[point] = c;
}

unsigned char SNMPpacket::get_pdu_len(){
	unsigned int point;
	point = 7 + (unsigned int)packet[6] + 1;
	return (unsigned char)(packet[point]);
}

void SNMPpacket::set_pdu_len(unsigned char c){
	unsigned int point;
	point = 7 + (unsigned int)packet[6] + 1;
	packet[point] = c;
}

unsigned char SNMPpacket::get_reqid_type(){
	unsigned int point;
	point = 7 + (unsigned int)packet[6] + 2;
	return (unsigned char)(packet[point]);
}
unsigned char SNMPpacket::get_reqid_len(){
	unsigned int point;
	point = 7 + (unsigned int)packet[6] + 3;
	return (unsigned char)(packet[point]);
}

unsigned char* SNMPpacket::get_reqid_p(){
	unsigned int point;
	point = 7 + (unsigned int)packet[6] + 4;
	return packet+point;
}

unsigned char SNMPpacket::get_errst(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]) + 2;
	return (unsigned char)p[0];
}

void SNMPpacket::set_errst(unsigned char c){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]) + 2;
	p[0] = c;
}

unsigned char SNMPpacket::get_errin(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p) + 2;
	return (unsigned char)p[0];
}

void SNMPpacket::set_errin(unsigned char c){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p) + 2;
	p[0] = c;
}

unsigned char SNMPpacket::get_varib_type(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p = get_next_p(p);
	return (unsigned char)p[0];
}


unsigned char SNMPpacket::get_varib_len(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p = get_next_p(p);
	return (unsigned char)p[1];
}

unsigned char* SNMPpacket::get_varib_p(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p = get_next_p(p);
	return p + 2;
}


unsigned char SNMPpacket::get_value_type(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p = get_next_p(p);
	p = get_next_p(p);
	return (unsigned char)p[0];
}

unsigned char SNMPpacket::get_value_len(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p = get_next_p(p);
	p = get_next_p(p);
	return (unsigned char)p[1];
}

unsigned char* SNMPpacket::get_value_p(){
	unsigned int point;
	unsigned char *p;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p = get_next_p(p);
	p = get_next_p(p);
	return p + 2;
}

void SNMPpacket::set_value(unsigned char type,unsigned char len,unsigned char *data){
	unsigned int point;
	unsigned char *p;
	unsigned char k;
	point = 7 + (unsigned int)packet[6] + 2;
	p = get_next_p(&packet[point]);
	p = get_next_p(p);
	p[4] = p[4] + len;
	p[6] = p[6] + len;
	p = get_next_p(p);
	p = get_next_p(p);
	p[0] = type;
	p[1] = len;
	for(k = 0;k < len;k++){
		p[k+2] = data[k];
	}	
}

ICMPpacket::ICMPpacket()
{
	packet = NULL;
	h_icmp = NULL;
	length = 0;
}

void ICMPpacket::init()
{
	packet = NULL;
	h_icmp = NULL;
	length = 0;
}

void ICMPpacket::setpacket(unsigned char *p)
{
	packet = p;
	h_icmp = (struct icmp_erhdr*)packet;
}

void ICMPpacket::setlen(unsigned int len)
{
	length = len;
}

int ICMPpacket::checksum()
{
	unsigned short *h_icmp_chksum;
	unsigned int recv_sum,calc_sum;
	unsigned int icmp_len;
	unsigned long sum = 0;
	if(packet == NULL){
		return -1;
	}
    	recv_sum = h_icmp->chksum;
	//Serial.println(recv_sum,HEX);
	icmp_len = length;
	h_icmp->chksum = 0x0000;
	h_icmp_chksum = (unsigned short*)packet;
	while( icmp_len > 1 ){
		sum += *h_icmp_chksum;
		h_icmp_chksum++;
		icmp_len -= 2;
	}
	if( icmp_len == 1 ){
		sum += *(unsigned char *)h_icmp_chksum;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	calc_sum = (unsigned short)(~sum);
	//Serial.println(calc_sum,HEX);
	h_icmp->chksum = recv_sum;
	if(recv_sum == calc_sum){
		return 1;
	}
	else{
		h_icmp->chksum = calc_sum;
		return 0;
	}
}

unsigned char ICMPpacket::gettype()
{
	return h_icmp->type;
}

void ICMPpacket::settype(unsigned char _type)
{
	h_icmp->type = _type;
}

unsigned char ICMPpacket::getcode()
{
	return h_icmp->code;
}

void ICMPpacket::setcode(unsigned char _code)
{
	h_icmp->code = _code;
}

unsigned short ICMPpacket::getid()
{
	return ntohsk(h_icmp->id);
}

void ICMPpacket::setid(unsigned short _id)
{
	h_icmp->id = ntohsk(_id);
}

unsigned short ICMPpacket::getsnumber()
{
	return ntohsk(h_icmp->snumber);
}

void ICMPpacket::setsnumber(unsigned short _snumber)
{
	h_icmp->snumber = ntohsk(_snumber);
}

unsigned char* ICMPpacket::get_payload_er_s()
{
	return packet+8;
}

unsigned char* ICMPpacket::get_payload_s()
{
	return packet+4;
}

unsigned char* ICMPpacket::geticmphdr()
{
	return packet;
}

int ICMPpacket::set_payload_er(unsigned int len,unsigned char *data)
{
	unsigned char *h_payload;
	int i;
	h_payload = (unsigned char*)(packet+8);
	if(packet == NULL){
		return -1;
	}
	for(i = 0;i < len;i++){
		h_payload[i] = data[i];
	}
	return i;

}

int ICMPpacket::set_payload(unsigned int len,unsigned char *data)
{
	unsigned char *h_payload;
	int i;
	h_payload = (unsigned char*)(packet+4);
	if(packet == NULL){
		return -1;
	}
	for(i = 0;i < len;i++){
		h_payload[i] = data[i];
	}
	return i;

}



UDPpacket::UDPpacket()
{
	packet = NULL;
	fake.ip_src = NULL;
	h_udp = NULL;
}

void UDPpacket::init()
{
	packet = NULL;
	fake.ip_src = NULL;
	h_udp = NULL;
}

void UDPpacket::setpacket(unsigned char *p){
	packet = p;
	h_udp = (struct udphdr*)(packet);
}
void UDPpacket::setfake(
		unsigned long _ip_src,
		unsigned long _ip_dst)
{
	fake.ip_src = _ip_src;
	fake.ip_dst = _ip_dst;
	fake.pad = 0x00;
	fake.ip_p = 17;
}

void UDPpacket::setport(
		unsigned int _udp_src,
		unsigned int _udp_dst)
{
	h_udp->udp_src = _udp_src;
	h_udp->udp_dst = _udp_dst;
}

int UDPpacket::checksum()
{
	unsigned short *h_udp_chksum;
	unsigned short *h_fake_chksum;
	unsigned int recv_sum,calc_sum;
	unsigned int udp_len;
	unsigned long sum = 0;
	int fake_len = 12;

	if(fake.ip_src == NULL){
		return -1;
	}
	else if(packet == NULL){
		return -1;
	}

	fake.udp_len = h_udp->udp_len;
	recv_sum = h_udp->udp_sum;
	udp_len = ntohsk(h_udp->udp_len);
	h_fake_chksum = (unsigned short*)(&fake);
	h_udp_chksum = (unsigned short*)packet;
	h_udp->udp_sum = 0x0000;
	while(fake_len > 1){
		sum+= *h_fake_chksum;
		h_fake_chksum++;
		fake_len-=2;
	}
	while( udp_len > 1 ){
		sum += *h_udp_chksum;
		h_udp_chksum++;
		udp_len -= 2;
	}
	if( udp_len == 1 ){
		sum += *(unsigned char *)h_udp_chksum;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	calc_sum = (unsigned short)(~sum);
	h_udp->udp_sum = recv_sum;
	if(recv_sum == calc_sum){
		return 1;
	}
	else{
		h_udp->udp_sum = calc_sum;
		return 0;
	}
}

unsigned char* UDPpacket::get_payload_s()
{
	return (packet+8);
}

unsigned char* UDPpacket::getudphdr()
{
	return packet;
}

unsigned int UDPpacket::getlen()
{
	return (ntohsk(h_udp->udp_len));
}

unsigned int UDPpacket::getdstport()
{
	return (ntohsk(h_udp->udp_dst));
}
void UDPpacket::setlen(unsigned int len)
{
	h_udp->udp_len = ntohsk(len);
}

int UDPpacket::set_payload(unsigned int len,unsigned char *data)
{
	unsigned char *h_payload;
	int i;
	h_payload = (unsigned char*)(packet+8);
	if(packet == NULL){
		return -1;
	}
	for(i = 0;i < len;i++){
		h_payload[i] = data[i];
	}
	h_udp->udp_len = ntohsk(len+8);
	return i;
}

IPpacket::IPpacket()
{
	packet = NULL;
	h_ip = NULL;
}

void IPpacket::init()
{
	packet = NULL;
	h_ip = NULL;
}

void IPpacket::setpacket(unsigned char *p){
	packet = p;
	h_ip = (struct iphdr*)packet;
}

int IPpacket::checksum()
{
	unsigned short *h_ip_chksum;
	unsigned int recv_sum,calc_sum;
	unsigned int ip_hdrlen;
	unsigned long sum = 0;
	if(packet == NULL){
		return -1;
	}
    	recv_sum = h_ip->ip_sum;
        ip_hdrlen = (((unsigned char)(h_ip->ip_vhl))&0x0F)*4;
	h_ip->ip_sum = 0x0000;
	h_ip_chksum = (unsigned short*)packet;
	while( ip_hdrlen > 1 ){
		sum += *h_ip_chksum;
		h_ip_chksum++;
		ip_hdrlen -= 2;
	}
	if( ip_hdrlen == 1 ){
		sum += *(unsigned char *)h_ip_chksum;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	calc_sum = (unsigned short)(~sum);
	h_ip->ip_sum = recv_sum;
	if(recv_sum == calc_sum){
		return 1;
	}
	else{
		h_ip->ip_sum = calc_sum;
		return 0;
	}
}

void IPpacket::setdefaulthdr()
{
	h_ip->ip_vhl = 0x45;
	h_ip->ip_tos = 0;
	h_ip->ip_len= 0x0000;
	h_ip->ip_id = (unsigned int)(random(0,65535));
	h_ip->ip_off = ntohsk(0x4000);//Don't flagment
	h_ip->ip_ttl = 64;
	h_ip->ip_p = 0;
	h_ip->ip_sum = 0x0000;
	h_ip->ip_src = 0x00000000;
	h_ip->ip_dst = 0x00000000;
}

void IPpacket::setproto(unsigned char proto){
	h_ip->ip_p = proto;
}

void IPpacket::setaddr(unsigned long src_addr,unsigned long dst_addr)
{
	h_ip->ip_src = src_addr;
	h_ip->ip_dst = dst_addr;
}

void IPpacket ::setlen(unsigned int len)
{
	h_ip->ip_len = ntohsk(len);
}

unsigned char* IPpacket::getiphdr()
{
	return packet;
}

unsigned char* IPpacket::get_payload_s()
{
	return packet+20;
}

unsigned int IPpacket::get_total_len()
{
	return ntohsk(h_ip->ip_len);
}

unsigned int IPpacket::get_hdr_len()
{
	return (((unsigned char)(h_ip->ip_vhl))&0x0F)*4;
}

Frame::Frame()
{
	p_length = 0;
	h_frame = NULL;
	hdr_length = 0;
	t_length = 0;
}

void Frame::init()
{
	p_length = 0;
	h_frame = NULL;
	hdr_length = 0;
	t_length = 0;
}

void Frame::setframe(unsigned char *p)
{
	h_frame = p;
}

void Frame::set_total_len(unsigned int len)
{
	t_length = len;
}

void Frame::set_payload_len(unsigned int len)
{
	p_length = len;
}

void Frame::sethdr(int type,int next)
{
	h_frame[0] = 3;//hdr_len
	h_frame[1] = 1;//type
	h_frame[2] = 4;//next hdr
	hdr_length = 3;
}

unsigned char* Frame::getiphdr()
{
	unsigned int i=0;
	if(h_frame == NULL){
		return NULL;
	}
	if(t_length > p_length+hdr_length){
		while(i < t_length){
			if(h_frame[i+2] == 4){
				i = i + h_frame[i];
				break;
			}
			else{
				i = i + h_frame[i];
			}
		}
		if(i >t_length){
			return NULL;
		}
	}
	else{
		while(i < hdr_length+p_length){
			if(h_frame[i+2] == 4){
				i = i + h_frame[i];
				break;
			}
			else{
				i = i + h_frame[i];
			}
		}
		if(i > hdr_length+p_length){
			return NULL;
		}
	}
	return h_frame+i;
}

unsigned int Frame::getfrlen_nocrc(){
	return hdr_length+p_length;
}

unsigned int Frame::getfrlen_withcrc(){
	return hdr_length+p_length+2;
}

int Frame::checkcrc()
{
}

void Frame::setcrc()
{
	unsigned int crc16 = 0xFFFFU;
	unsigned short r_crc;
  	unsigned long i;
	unsigned long lNum = hdr_length+p_length;
	int j;
	for ( i = 0 ; i < lNum ; i++ ){
		crc16 ^= (unsigned int)h_frame[i];
		for ( j = 0 ; j < 8 ; j++ ){
			if ( crc16 & 0x0001 ){
				crc16 = (crc16 >> 1) ^ 0xA001;
			}else{
				crc16 >>= 1;
			}
		}
	}
	r_crc = (unsigned short)(crc16);
	h_frame[lNum] = (unsigned char)(((unsigned short)r_crc)&0x0ff);
	h_frame[lNum+1] = (unsigned char)((((unsigned short)r_crc)>>8)&0x0ff);
}
Net_util::Net_util()
{
}

unsigned long Net_util::ntohl(unsigned long source)
{
  unsigned long result;
  unsigned char *bytes_s;
  unsigned char *bytes_r;
  bytes_s = (unsigned char*)(&source);
  bytes_r = (unsigned char*)(&result);
  bytes_r[0] = bytes_s[3];
  bytes_r[1] = bytes_s[2];
  bytes_r[2] = bytes_s[1];
  bytes_r[3] = bytes_s[0];
  return result;
}
unsigned int Net_util::ntohs(unsigned int source)
{
  unsigned int result;
  unsigned char *bytes_s;
  unsigned char *bytes_r;
  bytes_s = (unsigned char*)(&source);
  bytes_r = (unsigned char*)(&result);
  bytes_r[0] = bytes_s[1];
  bytes_r[1] = bytes_s[0];
  return result;
}

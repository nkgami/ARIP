#include <ARIP.h>
#include <pt.h>

#define BUADRATE 115200
#define BUFMAX 300
#define QUEMAX 1000
#define LENMAX 75

#define IPLENMAX 9999

//node settings
#define IPADDR 0x050BA8C0//192.168.11.*
#define BRADDR 0xFF0BA8C0//broadcast
#define NODENAME "node4"
#define INTERFRAMEGAP 1000//us
#define CSMAWAIT 60//ms, max wait

#define DEBUG 0

static struct pt pt1,pt2;

//for readque (ring buffer)
static unsigned char readque_s[QUEMAX];
static unsigned int readque_len[LENMAX];
static unsigned int readque_end=0;
static unsigned int readlen_end=0;
static unsigned int readque_lest=0;
static unsigned int readque_st=0;
static unsigned int readlen_st=0;

//for readque (ring buffer)
static unsigned char sendque_s[QUEMAX];
static unsigned int sendque_len[LENMAX];
static unsigned int sendque_end=0;
static unsigned int sendlen_end=0;
static unsigned int sendque_lest=0;
static unsigned int sendque_st=0;
static unsigned int sendlen_st=0;

//for timer
struct s_timer { unsigned long expiration; };
static void timer_set(struct s_timer *t, int interval) {
	// Use signed math with expiration to avoid millis rollover issues.
	t->expiration = millis() + interval;
}
static int timer_expired(const struct s_timer *t) {
	return (long)(millis() - t->expiration) >= 0;
}

struct s_utimer { unsigned long expiration; };
static void utimer_set(struct s_utimer *t, int interval) {
	// Use signed math with expiration to avoid millis rollover issues.
	t->expiration = micros() + interval;
}

static unsigned int utimer_expired(const struct s_utimer *t) {
	return (long)(micros() - t->expiration) >= 0;
}

//ip_addr
static unsigned long ip_addr=IPADDR;
static unsigned long br_addr=BRADDR;

//snmp
static char node_name[] = NODENAME;
static long uptime;

//enqueue
unsigned int enque(
		unsigned char* buf,
		unsigned char* que_s,
		unsigned int* que_len,
		unsigned int len,
		unsigned int* len_end,
		unsigned int* que_end,
		unsigned int* que_lest)
{
	unsigned int i;
	que_len[*len_end] = len;
	if (*len_end == LENMAX-1){
		(*len_end) = 0;
	}else{
		(*len_end)+=1;
	}
	for(i = 0;i < len;i++){
		if (i+(*que_end) >= QUEMAX){
			que_s[i+(*que_end) - QUEMAX] = buf[i];
		}
		else{
			que_s[i+(*que_end)] = buf[i];
		}
	}
	if (len +(*que_end) >= QUEMAX){
		(*que_end) = len +(*que_end) - QUEMAX;
	}
	else{
		(*que_end) = len +(*que_end);
	}
	(*que_lest)+= 1;
	return len;
}

//dequeue
unsigned int deque(
		unsigned char* buf,
		unsigned char* que_s,
		unsigned int* que_len,
		unsigned int* len_st,
		unsigned int* que_st,
		unsigned int* que_lest)
{
	unsigned int i;
	unsigned int len;
	len = que_len[*len_st];
	if (*len_st == LENMAX-1){
		(*len_st) = 0;
	}else{
		(*len_st)+=1;
	}
	for(i = 0;i < len;i++){
		if (i+(*que_st) >= QUEMAX){
			buf[i] = que_s[i+(*que_st) - QUEMAX];
		}
		else{
			buf[i] = que_s[i+(*que_st)];
		}
	}
	if (len +(*que_st) >= QUEMAX){
		(*que_st) = len +(*que_st) - QUEMAX;
	}
	else{
		(*que_st) = len +(*que_st);
	}
	(*que_lest) -= 1;
	return len;
}

//output crc of data
unsigned short crc( unsigned const char *pData, unsigned long lNum )
{
	unsigned int crc16 = 0xFFFFU;
	unsigned long i;
	int j;
	for ( i = 0 ; i < lNum ; i++ ){
		crc16 ^= (unsigned int)pData[i];
		for ( j = 0 ; j < 8 ; j++ ){
			if ( crc16 & 0x0001 ){
				crc16 = (crc16 >> 1) ^ 0xA001;
			}else{
				crc16 >>= 1;
			}
		}
	}
	return (unsigned short)(crc16);
}

// the setup routine runs once when you press reset:
void setup() {
	pinMode(35,OUTPUT);
	pinMode(36,OUTPUT);
	pinMode(13,OUTPUT);
	pinMode(12,OUTPUT);
	pinMode(11,OUTPUT);
	pinMode(10,OUTPUT);
	randomSeed(analogRead(1));
	// initialize serial communication at 9600 bits per second:
	Serial3.begin(BUADRATE);
	Serial.begin(9600);
	/*while(1){//wait for serial open
		if (Serial.available() > 0){
		break;
		}
		}*/
	PT_INIT(&pt1);
	PT_INIT(&pt2);
}

//thread for processing received packet
static int thread_send(struct pt *pt){
	static unsigned int len;
	static unsigned char buf[BUFMAX];
	static unsigned char sendbuf[BUFMAX];

	static struct iphdr *h_ip;
	static struct udphdr *h_udp;

	static unsigned short udp_len;

	static ICMPpacket icmp1,icmp2;
	static UDPpacket udp1,udp2;
	static IPpacket ip1,ip2;
	static SNMPpacket snmp1,snmp2;
	static Frame fr1,fr2;
	static Net_util nutil;
	static unsigned char *frame_payload;

	static unsigned char data[5];
	static unsigned int *short_data;
	static unsigned char *recv_udp;
	static unsigned int aread;
	static unsigned int avg_count,i;
	static s_timer onoff_timer;
	static int j;
	static long temp,voltage;

	PT_BEGIN(pt);
	Serial.print("thread_send start\n");
	while(1){
		PT_WAIT_UNTIL(pt,readque_lest > 0);
		noInterrupts();
		len = deque(buf,readque_s,readque_len,&readlen_st,&readque_st,&readque_lest);
		interrupts();
		//process packet received
		fr1.init();
		fr1.setframe(buf);
		fr1.set_total_len(len);
		frame_payload = fr1.getiphdr();
		ip1.init();
		ip1.setpacket(fr1.getiphdr());
		h_ip = (struct iphdr*)(ip1.getiphdr());
		if (ip1.checksum()==1){//chksum ok
			if (h_ip->ip_dst == ip_addr || h_ip->ip_dst == br_addr){//if dst adress is broadcast or this node
				if (h_ip->ip_p == 1){//ICMP
					icmp1.init();
					icmp1.setpacket(ip1.get_payload_s());
					icmp1.setlen(ip1.get_total_len()-ip1.get_hdr_len());

					if (icmp1.checksum() == 1){

						fr2.init();
						fr2.setframe(sendbuf);
						fr2.sethdr(1,4);

						ip2.init();
						ip2.setpacket(fr2.getiphdr());
						ip2.setdefaulthdr();
						ip2.setproto(1);
						ip2.setaddr(ip_addr,h_ip->ip_src);

						//set ip_len
						ip2.setlen(nutil.ntohs(h_ip->ip_len));

						//ip_checksum
						ip2.checksum();

						icmp2.init();
						icmp2.setpacket(ip2.get_payload_s());
						icmp2.settype(0x00);
						icmp2.setcode(0x00);
						icmp2.setlen(ip2.get_total_len()-ip2.get_hdr_len());
						icmp2.set_payload(ip2.get_total_len()-ip2.get_hdr_len(),icmp1.get_payload_s());


						//icmp_checksum
						icmp2.checksum();

						//set frame_len
						fr2.set_payload_len(ip2.get_total_len());

						//add_crc
						fr2.setcrc();

						noInterrupts();
						enque(sendbuf,sendque_s,sendque_len,fr2.getfrlen_withcrc(),&sendlen_end,&sendque_end,&sendque_lest);
						interrupts();
					}
				}
				else if (h_ip->ip_p == 17){//UDP
					udp1.init();
					udp1.setpacket(ip1.get_payload_s());
					udp1.setfake(h_ip->ip_src,h_ip->ip_dst);
					h_udp = (struct udphdr*)(udp1.getudphdr());
					udp_len = udp1.getlen();

					if (udp1.checksum() == 1){//udp checksum ok
						if(udp1.getdstport() == 161){//SNMP
							Serial.println("snmp");

							snmp1.setpacket(udp1.get_payload_s());

							fr2.init();
							fr2.setframe(sendbuf);
							fr2.sethdr(1,4);

							ip2.init();
							ip2.setpacket(fr2.getiphdr());
							ip2.setdefaulthdr();
							ip2.setproto(17);
							ip2.setaddr(ip_addr,h_ip->ip_src);

							udp2.init();
							udp2.setpacket(ip2.get_payload_s());
							udp2.setport(h_udp->udp_dst,h_udp->udp_src);

							//for snmp packet
							udp2.set_payload(udp_len-8,udp1.get_payload_s());
							snmp2.setpacket(udp2.get_payload_s());
							if(((snmp1.get_varib_p())[6]) == 0x01){//sysDscr
								snmp2.set_value(0x04,0x05,(unsigned char*)node_name);
								snmp2.set_errin(0x00);
								snmp2.set_errst(0x00);
								snmp2.set_pdu_len(snmp1.get_pdu_len()+0x05);
								snmp2.set_pdu_type(0xA2);
								snmp2.set_length(snmp1.get_length()+0x05-0x02);
								udp_len += 5;
								udp2.setlen(udp_len);
							}
							else if(((snmp1.get_varib_p())[6]) == 0x03){//sysUptime
								uptime = millis()/10;
								uptime = nutil.ntohl(uptime);
								snmp2.set_value(0x43,0x04,(unsigned char*)(&uptime));
								snmp2.set_errin(0x00);
								snmp2.set_errst(0x00);
								snmp2.set_pdu_len(snmp1.get_pdu_len()+0x04);
								snmp2.set_pdu_type(0xA2);
								snmp2.set_length(snmp1.get_length()+0x04-0x02);
								udp_len += 4;
								udp2.setlen(udp_len);
							}
							else if(((snmp1.get_varib_p())[3]) == 0x04 && ((snmp1.get_varib_p())[5]) == 0x09){//sysUptime
								voltage = analogRead(0);
								voltage = voltage * 5000;
								voltage = voltage / 1023;
								temp = (voltage-600)/10;
								temp = nutil.ntohl(temp);
								snmp2.set_value(0x02,0x04,(unsigned char*)(&temp));
								snmp2.set_errin(0x00);
								snmp2.set_errst(0x00);
								snmp2.set_pdu_len(snmp1.get_pdu_len()+0x04);
								snmp2.set_pdu_type(0xA2);
								snmp2.set_length(snmp1.get_length()+0x04-0x02);
								udp_len += 4;
								udp2.setlen(udp_len);
							}
							else{
								snmp2.set_pdu_type(0xA2);
								snmp2.set_errin(0x01);
								snmp2.set_errst(0x02);
							}
						}
						else{//other routines for UDP packet
							fr2.init();
							fr2.setframe(sendbuf);
							fr2.sethdr(1,4);

							ip2.init();
							ip2.setpacket(fr2.getiphdr());
							ip2.setdefaulthdr();
							ip2.setproto(17);
							ip2.setaddr(ip_addr,h_ip->ip_src);

							udp2.init();
							udp2.setpacket(ip2.get_payload_s());
							udp2.setport(h_udp->udp_dst,h_udp->udp_dst);

							recv_udp = udp1.get_payload_s();
							if(recv_udp[0] == 0x00){
								data[0] = recv_udp[1];
								data[1] = recv_udp[2];
								udp_len = 8+2;
								udp2.set_payload(udp_len-8,data);
							}
							else if(recv_udp[0] == 0x01){
								aread = analogRead(recv_udp[1]);
								short_data = (unsigned int*)data;
								short_data[0] = nutil.ntohs(aread);
								udp_len = 8+2;
								udp2.set_payload(udp_len-8,data);
							}
							else if(recv_udp[0] == 0x02){
								avg_count = recv_udp[2];
								aread = 0;
								for(i = 0;i < avg_count;i++){
									aread += analogRead(recv_udp[1]);
								}
								aread = aread/avg_count;
								short_data = (unsigned int*)data;
								short_data[0] = nutil.ntohs(aread);
								udp_len = 8+2;
								udp2.set_payload(udp_len-8,data);
							}
							else if(recv_udp[0] == 0x03){
								if(recv_udp[2] == 0x01){
									digitalWrite(recv_udp[1],HIGH);
									data[0] = 1;
								}
								else if(recv_udp[2] == 0x00){
									digitalWrite(recv_udp[1],LOW);
									data[0] = 1;
								}
								else{
									data[0] = 0;
								}
								udp_len = 8+1;
								udp2.set_payload(udp_len-8,data);
							}
							else if(recv_udp[0] == 0x04){
								digitalWrite(recv_udp[1],HIGH);
								timer_set(&onoff_timer,recv_udp[2]*100);
								PT_WAIT_UNTIL(pt,timer_expired(&onoff_timer));
								digitalWrite(recv_udp[1],LOW);
								data[0] = 1;
								udp_len = 8+1;
								udp2.set_payload(udp_len-8,data);
							}
							else if(recv_udp[0] == 0x05){
								digitalWrite(recv_udp[1],LOW);
								timer_set(&onoff_timer,recv_udp[2]*100);
								PT_WAIT_UNTIL(pt,timer_expired(&onoff_timer));
								digitalWrite(recv_udp[1],HIGH);
								data[0] = 1;
								udp_len = 8+1;
								udp2.set_payload(udp_len-8,data);
							}
							else{
								udp2.set_payload(udp_len-8,udp1.get_payload_s());
							}
						}//the end of if-else of port number
						//udp_checksum
						udp2.setfake(ip_addr,h_ip->ip_src);
						udp2.checksum();

						//set ip_len
						ip2.setlen(udp_len+20);

						//ip_checksum
						ip2.checksum();

						//set frame_len
						fr2.set_payload_len(20+udp_len);

						//add_crc
						fr2.setcrc();

						noInterrupts();
						enque(sendbuf,sendque_s,sendque_len,fr2.getfrlen_withcrc(),&sendlen_end,&sendque_end,&sendque_lest);
						interrupts();
					}
				}
			}

		}
	}
	PT_END(pt);
}

//thread for receiving packet from serial (RS485)
static int thread_read(struct pt *pt){
	static unsigned char c;
	static unsigned char readbuf[BUFMAX];
	static unsigned int send_len;
	static struct iphdr *h_ip;
	static struct icmp_erhdr *h_icmp;
	static unsigned char ip_len_1;
	static unsigned char ip_len_2;
	static unsigned short c_crc;
	static unsigned int ct;
	static unsigned long packet_len = 0;
	static unsigned int ip_len=IPLENMAX;
	static unsigned char ip_hlen;
	static s_utimer timeout,timeout3;
	PT_BEGIN(pt);
	ct = 0;
	Serial.print("thread_read start\n");
	while(1){
		utimer_set(&timeout,INTERFRAMEGAP);//wait for data
		PT_WAIT_UNTIL(pt,Serial3.available() || utimer_expired(&timeout));
		if (utimer_expired(&timeout)){//timeout and reset
			#if DEBUG
			Serial.write("timeout\n");
			#endif			
			//reset param
			ct = 0;
			packet_len = 0;
			ip_len=IPLENMAX;
			if (sendque_lest > 0){//if there are any data on queue
				utimer_set(&timeout3,(random(0,1000)*CSMAWAIT));//random wait
				PT_WAIT_UNTIL(pt,Serial3.available() || utimer_expired(&timeout3));
				if (Serial3.available()){
					continue;
				}
				//Serial.print("thrr-deq_");
				noInterrupts();//read from queue
				send_len = deque(readbuf,sendque_s,sendque_len,&sendlen_st,&sendque_st,&sendque_lest);
				interrupts();
				//Serial.print("len:");
				//Serial.println(send_len,DEC);
				//send to serial
				#if DEBUG
				Serial.write("Send\n");
				#endif
				digitalWrite(35,HIGH); 
				digitalWrite(36,HIGH);
				Serial3.write(readbuf,send_len);
				Serial3.flush();
				digitalWrite(35,LOW); 
				digitalWrite(36,LOW);
			}
		}
		else{
			c = Serial3.read();
			readbuf[ct] = c;
			noInterrupts();
			ct += 1;
			interrupts();
			#if DEBUG
			Serial.write("0x");
			Serial.print(c,HEX);
			Serial.write(" ");
			#endif
			if (ct == 1){//header_len
				#if DEBUG
				Serial.print(c,HEX);
				Serial.write(",");
				#endif
				packet_len += (unsigned long)c;
			}
			else if (ct == 2){//header_type
				#if DEBUG
				Serial.print(c,HEX);
				Serial.write(",");
				#endif
			}
			else if (ct == 3){//next_headr
				#if DEBUG
				Serial.print(c,HEX);
				Serial.write("\n");
				#endif
			}
			else if (ct == 6){
				ip_len_1 = c;
			}
			else if (ct == 7){
				ip_len_2 = c;
				ip_len = ((unsigned int)(ip_len_1)<<8)+(unsigned int)(ip_len_2);
				packet_len += ((unsigned long)ip_len);
				#if DEBUG
				Serial.write("IPlen:");
				Serial.print(ip_len,DEC);
				Serial.write("\n");
				#endif
			}
			else if (ct == (int)ip_len+5){
				#if DEBUG
				Serial.print((int)ip_len+5,DEC);
				Serial.write(" end\n");
				Serial.write("last:");
				Serial.print(c,DEC);
				Serial.write("\n");
				#endif
				//end of receiving
				h_ip = (iphdr*)(&readbuf[readbuf[0]]);
				//CRC_check
				c_crc = crc(readbuf,packet_len);
				if (readbuf[packet_len]==(c_crc&0xff)
						&& readbuf[packet_len+1]==((c_crc>>8)&0xff)){
					#if DEBUG
					Serial.write("CRC_OK\n");
					#endif
					//receiving sequence
					h_ip = (struct iphdr*)(readbuf+3);
					#if DEBUG
					Serial.println("thrr_enq");
					#endif 
					noInterrupts();
					enque(readbuf,readque_s,readque_len,packet_len,&readlen_end,&readque_end,&readque_lest);
					interrupts();
					#if DEBUG
					Serial.print("rque_ls:");
					Serial.println(readque_lest,DEC);
					#endif
				}
				else{
					#if DEBUG
					Serial.write("CRC_NG\n");
					#endif
				}
				//reset param
				ct = 0;
				packet_len = 0;
				ip_len=IPLENMAX;
			}
		}
	}
	PT_END(pt);
}

// the loop routine runs over and over again forever:
void loop() {
	thread_read(&pt1);
	thread_send(&pt2);
}





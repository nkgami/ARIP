#ifndef ARIP_h
#define ARIP_h
#include "ARIP_IP.h"
#include "ARIP_UDP.h"
#include "ARIP_ICMP.h"
#include "ARIP_SNMP.h"
#include "ARIP_IP485.h"

//Utility
class Net_util
{
  public:
    Net_util();
    unsigned long ntohl(unsigned long source);
    unsigned int ntohs(unsigned int source);
};
#endif

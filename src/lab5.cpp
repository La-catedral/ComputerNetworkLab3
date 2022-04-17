/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysInclude.h"
#include <vector>
#include <iostream>

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

// implemented by students

typedef unsigned int uint;

struct route_struct
{
uint low;
uint high;
uint masklen;
uint next_ip; 

route_struct(uint low,uint high,uint masklen,uint next_ip){
this->low = low;
this->high = high;
this->masklen = masklen;
this->next_ip = next_ip;
}

};


vector <route_struct> router_table;

uint get_low(uint dst_ip,uint masklen)  // 子网下限
{
	masklen = 32 - masklen;
	uint low = dst_ip >> masklen;
	low = low<<8;
	return low;

}

uint get_high(uint dst_ip,uint masklen)  // 子网上限
{
	masklen = 32 - masklen;
	uint high = dst_ip | ((1 << masklen) - 1);
	return high;
}

void stud_Route_Init()
{
	router_table.clear();
	return;
}

void stud_route_add(stud_route_msg *proute)
{
	uint dest = ntohl(proute->dest);
	uint masklen = ntohl(proute->masklen);
	uint nexthop = ntohl(proute->nexthop);
	uint low = get_low(dest,masklen);
	uint high = get_high(dest,masklen);
	route_struct new_rou = route_struct(low,high,masklen,nexthop);
	router_table.push_back(new_rou);
	return;
}

bool get_next(uint dst,uint &nextIP)
{
	uint len = 0;
	bool result = false;
	for(int i = 0; i < router_table.size(); i++ )
	{
		route_struct thisone = router_table[i];
		if( thisone.low <= dst && dst <= thisone.high){
			if(thisone.masklen > len){
				len = thisone.masklen;
				nextIP = thisone.next_ip;
				result = true;
			}
		}
	}
	return result;
}

int stud_fwd_deal(char *pBuffer, int length)
{	typedef struct{
	char ver_ihl;
	char service_type;
	unsigned short total_lengtg;
	uint iden_off;
	char TTL;
	char protocal;
	unsigned short header_checksum;
	uint src_ip;
	uint trg_ip;
	}IPV4;
	
	IPV4* recv_point = (IPV4*)pBuffer;
	IPV4 recv_messa = *recv_point;
	uint TTL = recv_messa.TTL;
	uint checksum = recv_messa.header_checksum;
	uint trg_IP = ntohl(recv_messa.trg_ip);

	uint local_ip = getIpv4Address();
	if (trg_IP == local_ip || trg_IP == 0xffffffff){
		fwd_LocalRcv(pBuffer,length);
		return 0;
	}
	
	uint next_ip;
	if (get_next(trg_IP,next_ip)){
		if(TTL <= 0 ){ // 检查TTL
			fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
			return 1;
		}	
		TTL =TTL -  1;
		pBuffer[8] = (unsigned char)(TTL & 0xff);
		
		unsigned short check_calc = 0;
		for (int i = 0;i < 2 * 5;i++){
			if(i != 5){
				unsigned short this_num = ((unsigned short )(pBuffer[2*i] << 8) + ((unsigned short )pBuffer[2*i + 1]));
					if(this_num + check_calc > 0xffff ){
					check_calc += this_num + 1;
				}
				else{
					check_calc += this_num;
				}
			}
 		}
		unsigned short check_s = htons(0xffff-check_calc);
		memcpy(pBuffer+10,&check_s,2);

		fwd_SendtoLower(pBuffer, length, next_ip);
    		return 0;
		}
	else{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
    		return 1;
	}
}


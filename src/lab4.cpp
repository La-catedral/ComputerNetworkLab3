/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"
#include <stdio.h>
#include <stdlib.h>


extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students

int stud_ip_recv(char *pBuffer,unsigned short length)  // pBuffer 为指向接收缓冲区的指针 length: the length of ipv4 group
{
	typedef struct{
	char ver_ihl;
	char service_type;
	unsigned short total_lengtg;
	unsigned int iden_off;
	char TTL;
	char protocal;
	unsigned short header_checksum;
	unsigned int src_ip;
	unsigned int trg_ip;
	}IPV4;
	
	IPV4* recv_point = (IPV4*)pBuffer;
	IPV4 recv_messa = *recv_point;
	
	int  version  = recv_messa.ver_ihl >> 4 ; //版本号
	int head_length = recv_messa.ver_ihl & 0xf;
	int TTL = recv_messa.TTL;
	int checksum = recv_messa.header_checksum;
	int trg_IP = ntohl(recv_messa.trg_ip);
	
	if(version != 4){
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_VERSION_ERROR);
		return 1;
	}
	
	if(head_length < 5){  //header length
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_HEADLEN_ERROR);
		return 1;
	}
	
	if(TTL <= 0){  //TTL
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_TTL_ERROR);
		return 1;
	}
	
	if( !(trg_IP == getIpv4Address() || trg_IP == 0xffffffff)){  //判断目的IP是否为本机IP或广播地址
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
		return 1;
	}

	unsigned short check_calc = 0;
	
	for (int i = 0;i < 2 * head_length;i++){
		unsigned short this_num = (int)((unsigned char)(pBuffer[2*i]) << 8) + (int)((unsigned char)pBuffer[2*i+1]);
		if(this_num + check_calc > 0xffff ){
			check_calc += this_num + 1;
		}
		else{
			check_calc += this_num;
		}
 	}
	

	if(check_calc != 0xffff){		
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_CHECKSUM_ERROR);
		return 1;
	}

	ip_SendtoUp(pBuffer,length);  //没问题就上传数据
	return 0;
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	char *pIpv4 = (char*)malloc((len+20)*sizeof(char));
	memset(pIpv4,0,len+20);
	pIpv4[0] = 0x45;
	unsigned short total_length = htons(len + 20);
	memcpy(pIpv4+2,&total_length , 2);
	unsigned int random_iden = rand() % 65535;
	memcpy(pIpv4+4,&random_iden,4);
	pIpv4[8] = ttl;
	pIpv4[9] = protocol;
	unsigned int src_ip = htonl(srcAddr);
	unsigned int trg_ip = htonl(dstAddr);
	memcpy(pIpv4+12,&src_ip,4);  //将源IP地址存入该区域
	memcpy(pIpv4+16,&trg_ip,4);  //将目标IP地址存入该区域
	
	unsigned short check_calc = 0;
	for (int i = 0;i < 2 * 5;i++){
		unsigned short this_num = ((unsigned char)(pIpv4[2*i]) << 8) + ((unsigned char)pIpv4[2*i+1]);
		if(this_num + check_calc > 0xffff ){
			check_calc += this_num + 1;
		}
		else{
			check_calc += this_num;
		}
 	}
	unsigned short check_s = htons(0xffff-check_calc);
	memcpy(pIpv4+10,&check_s,2);
	memcpy(pIpv4+20,pBuffer,len);
	ip_SendtoLower(pIpv4,len+20);

	return 0;
}

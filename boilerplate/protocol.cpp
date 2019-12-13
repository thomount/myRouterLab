#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <cstdio>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
 
uint32_t get(const uint8_t * packet, int start, int len) {		// for saving
	uint32_t ret = 0;
	for (int i = len-1; i >= 0; i--) {
		ret <<= 8;
		ret += packet[start + i];
	}
	return ret;
}
uint32_t get1(const uint8_t * packet, int start, int len) {		// for checking
	uint32_t ret = 0;
	for (int i = 0; i < len; i++) {
		ret <<= 8;
		ret += packet[start + i];
	}
	return ret;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
	// TODO:
	int head_len = (packet[0]&0xf)*4;	//byte
	int tot_len = (packet[3]+(packet[2]<<8));
	if (tot_len > len) return false;
	packet += head_len + 8;	//IP head and UDP head
	int n = (tot_len - head_len - 12) / 20;
	if (packet[0] != 1 && packet[0] != 2) return false;		//command illegal
	if (packet[1] != 2) return false;						//version illegal
	if (packet[2] != 0 || packet[3] != 0) return false;		//zero illegal
	int command = packet[0];	//1 request 2 response
	packet += 4;				//rip start
	for (int i = 0; i < n; i++) {
		int family = ((1ll*packet[20*i])<<8)+(1ll*packet[20*i+1]), tag = ((1ll*packet[20*i+3])<<8)+(1ll*packet[20*i+2]);
		if ((command == 2 && family != 2) || (command == 1 && family != 0) || tag != 0) return false;
		long long metric = get1(packet, 20*i+16, 4);
		if (metric < 1 || metric > 16) return false;
		long long mask = get1(packet, 20*i+8, 4);
		int tt = 0;
		while ((!(mask & 1)) && tt < 32) {
			mask >>= 1;
			tt ++;
		}
		while (mask & 1) {
			mask >>= 1;
			tt ++;
		}
		if (tt != 32) return false;
		
	}
	
	
	RipPacket * ret = output;
	ret->numEntries = n;
	ret->command = command;
	
	for (int i = 0; i < n; i++) {
		ret->entries[i].addr = 		get(packet,20*i+4,4);
		ret->entries[i].mask = 		get(packet,20*i+8, 4);
		ret->entries[i].nexthop = 	get(packet,20*i+12, 4);
		ret->entries[i].metric = 	get(packet,20*i+16, 4);
		printf("metric : %x %x %x %x = %d\n", packet[20*i+16], packet[20*i+17], packet[20*i+18], packet[20*i+19], ret->entries[i].metric);
	}
	return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
 
void put(uint8_t * buffer, int start, int len, uint32_t num) {
	for (int i = 0; i < len; i++) {
		buffer[start+i] = (num & 255);
		num >>= 8;
	}
}
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = buffer[3] = 0;
  buffer += 4;
  for (int i = 0; i < rip->numEntries; i++) {
	  buffer[20*i] = buffer[20*i+2] = buffer[20*i+3] = 0;
	  buffer[20*i+1] = (rip->command == 1)? 0: 2;
	  put(buffer, 20*i+4, 4, rip->entries[i].addr);
	  put(buffer, 20*i+8, 4, rip->entries[i].mask);
	  put(buffer, 20*i+12, 4, rip->entries[i].nexthop);
	  put(buffer, 20*i+16, 4, rip->entries[i].metric);
  }
  
  return 4+20*rip->numEntries;
}

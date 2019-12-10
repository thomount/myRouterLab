#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <cstdio>
using namespace std;

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
	// the real length is (packet[0]&0xf)*4 which names IHL
	len = (packet[0] & 0xf)*4;
	int sum = 0;
	for (int i = 0; i < len; i+=2) {
		sum += (packet[i]<<8)+packet[i+1];
		while (sum > 0xffff)
			sum = (sum >> 16) + (sum & 0xffff);
	}	
	return (sum == 0xffff);
}
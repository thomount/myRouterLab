#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern int Checksum(uint8_t *packet, size_t len);
extern std::vector<RoutingTableEntry> table;
uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};

void addHead(uint8_t * a, int totlen, uint32_t src, uint32_t dst) {
  a[0] = 0x45;
  a[1] = 0x00;    //TOS
  a[2] = totlen >> 8; a[3] = totlen & 255;    //totLen
  a[4] = a[5] = a[6] = a[7] = 0x00;           //ID & OFF
  a[8] = 0x0F;    //TTL
  a[9] = 0x11;    //UDP
  for (int i = 12; i < 16; i++, src >>= 8) a[i] = src & 255;
  for (int i = 16; i < 20; i++, dst >>= 8) a[i] = dst & 255;
  a[10] = a[11] = 0x00;
  int ret = ~Checksum(a, totlen);
  a[10] = ret >> 8;
  a[11] = ret & 0xff;
  a[20] = a[22] = 0x02; a[21] = a[23] = 0x08;   //UDP port
  totlen -= 20;
  a[24] = totlen >> 8; a[25] = totlen & 255;
  a[26] = a[27] = 0x00;
}
uint32_t reverse(uint32_t x) {
  uint32_t ret = 0;
  for (int i = 0; i < 4; i++, x >>= 8) {
    ret <<= 8;
    ret |= (x & 255);
  }
  return ret;
}

RipEntry getEntry(RoutingTableEntry x) {
  return {
    .addr = x.addr & ((1ll<<x.len)-1),
    .mask = (1ll<<x.len)-1, 
    .nexthop = x.nexthop,
    .metric = x.metric,
  };
}

void printRouterTable() {
  printf("Router table: \n");
  for (RoutingTableEntry x: table)
    printf("\t[addr = %x\tlen = %d\tmetric = %d\tnexthop = %x\tindex = %d]\n", x.addr, x.len, reverse(x.metric), x.nexthop, x.if_index);
}

void printHead(uint8_t *packet) {
  printf("Receive Head:  ");
  for (int i = 0; i < 32; i++) printf("%x ", packet[i]);
  printf("\n");
}
void printRip(RipPacket x) {
  printf("Rip Packet: num = %d\n", x.numEntries);
  for (int i = 0; i < x.numEntries; i++) {
    RipEntry y = x.entries[i];
    printf("  %2d: [addr = %x\tmask = %x\tmetric=%d\tnexthop = %x\t]\n", i, y.addr, y.mask, reverse(y.metric), y.nexthop);
  }
}
int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i], // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = reverse(1u),
    };
    update(true, entry);
  }

  // initial request

  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
		RipPacket rip;
		rip.command = 1;
		rip.numEntries = 1;
		rip.entries[0].addr = 0;
		rip.entries[0].mask = 0;
		rip.entries[0].metric = reverse(16u);
		rip.entries[0].nexthop = 0;
    addHead(output, 52, addrs[i], 0x090000e0);
		uint32_t rip_len = assemble(&rip, &output[20 + 8]);
		macaddr_t dst_mac;
		if (HAL_ArpGetMacAddress(i, 0x090000e0, dst_mac) == 0)
			HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
		else
			printf("WRONG! DST_MAC NOT FOUND!");

  }


  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      printf("10s Timer\n");
      printRouterTable();
      last_time = time;

      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        RipPacket rip;
        rip.command = 2;
        rip.numEntries = 0;
        for (RoutingTableEntry x: table) {
					if ((addrs[i] & ((1ll<<table[i].len)-1)) == (x.addr&((1ll<<x.len)-1))) continue;
					if (x.nexthop == addrs[i]) continue;
					if (x.if_index == i) continue;
          rip.entries[rip.numEntries++] = getEntry(x);
        }
        addHead(output, rip.numEntries*20+32, addrs[i], 0x090000e0);
        uint32_t rip_len = assemble(&rip, &output[20 + 8]);
        macaddr_t dst_mac;
        if (HAL_ArpGetMacAddress(i, 0x090000e0, dst_mac) == 0)
          HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
        else
          printf("WRONG! DST_MAC NOT FOUND!");
      }



    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {

      //TODO: additional validation check

      printf("Invalid IP Checksum\n");
      continue;
    } else {
      printHead(packet);
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // src_addr packet[12]-packet[15]
    // dst_addr packet[16]-packet[19]
    // big endian ???
    src_addr = (packet[15]<<24)+(packet[14]<<16)+(packet[13] << 8) + packet[12];
    dst_addr = (packet[19]<<24)+(packet[18]<<16)+(packet[17] << 8) + packet[16];

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // Handle rip multicast address(224.0.0.9)?
    if (dst_addr == 0x090000e0) dst_is_me = true;

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        printf("Dest is me and valid packet\n");
        printRip(rip);
        if (rip.command == 1) {
          printf("request\n");
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          if (rip.numEntries != 1 || reverse(rip.entries[0].metric) != 16) {
            printf("invalid request\n");
            continue;
          }

          RipPacket resp;
          // TODO: fill resp
          resp.numEntries = 0;
          resp.command = 2;                         
          for (RoutingTableEntry x: table) {
            if ((x.addr & ((1ll<<x.len)-1)) == (src_addr & ((1ll<<x.len)-1))) {
              if (x.if_index == if_index)
								continue;
              resp.entries[resp.numEntries++] = getEntry(x);
            }

          }

          addHead(output, resp.numEntries*20+32, addrs[if_index], src_addr);
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);

          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          printf("response\n");
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          bool hasupdate = false;
          for (int i = 0; i < rip.numEntries; i++) {
            RipEntry x = rip.entries[i];
            x.nexthop = (x.nexthop == 0)?src_addr: x.nexthop;
            x.metric = std::min(reverse(x.metric)+1, 16u);
            bool hasfound = false;
            for (RoutingTableEntry t: table) {
              RipEntry y = getEntry(t);
              if (y.mask != x.mask || y.addr != (x.addr&x.mask)) continue;
              hasfound = true;
              if (x.metric >= 16 && x.nexthop == y.nexthop) update(false, t);
              if (x.metric+1 < reverse(y.metric)) {
                hasupdate = true;
                RoutingTableEntry s = t;
                printf("update path %x metric = %d\n", x.addr, x.metric);
                s.addr = x.addr; s.metric = reverse(x.metric); s.nexthop = x.nexthop; s.if_index = if_index;
                update(true, s);
              }
              break;
            }
            if (!hasfound && x.metric < 16) {
              hasupdate = true;
              RoutingTableEntry s;
              printf("add path %x metric = %d\n", x.addr, x.metric);
              s.addr = x.addr; s.len = __builtin_popcount(x.mask); s.metric = reverse(x.metric); s.nexthop = src_addr; s.if_index = if_index;
              update(true, s);
            }
          }
          if (hasupdate) {
            printf("router table updated\n");
            for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
              RipPacket rip;
              rip.command = 2;
              rip.numEntries = 0;
              for (RoutingTableEntry x: table) {
                if ((addrs[i] & ((1ll<<table[i].len)-1)) == (x.addr&((1ll<<x.len)-1))) continue;
                if (x.nexthop == addrs[i]) continue;
                if (x.if_index == i) continue;
                rip.entries[rip.numEntries++] = getEntry(x);
              }
              addHead(output, rip.numEntries*20+32, addrs[i], 0x090000e0);
              uint32_t rip_len = assemble(&rip, &output[20 + 8]);
              macaddr_t dst_mac;
              if (HAL_ArpGetMacAddress(i, 0x090000e0, dst_mac) == 0)
                HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
              else
                printf("WRONG! DST_MAC NOT FOUND!");
            }
 
          }
        }
      } else {
        printf("dest is me but invalid packet\n");
      }
    } else {
      printf("dest is not me");
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          bool ret = forward(output, res);
          if(!ret) continue;
          
          if (output[8] > 0)
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          else {
            // TODO: 构造一个 ICMP Time Exceeded 返回给发送者
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
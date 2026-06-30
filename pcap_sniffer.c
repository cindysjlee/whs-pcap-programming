#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "myheader.h"

// pcap_loop에서 패킷 캡처 시마다 호출되는 콜백 함수
// Ethernet -> IP -> TCP -> HTTP 순서로 역캡슐화하여 각 헤더 정보 출력
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  // Ethernet 헤더
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) != 0x0800) // 0x0800 = IPv4
    return;

  // IP 헤더 (Ethernet 14바이트 뒤)
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  int ip_header_len = ip->iph_ihl * 4; // ihl * 4 = 실제 바이트 수

  // TCP만 처리
  if (ip->iph_protocol != IPPROTO_TCP)
    return;

  // TCP 헤더 (IP 헤더 뒤)
  struct tcpheader *tcp =
      (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
  int tcp_header_len = TH_OFF(tcp) * 4; // data offset 상위 4비트 * 4

  // HTTP payload 위치 계산
  int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len; // IP 전체 - 헤더들
  const u_char *payload =
      packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;

  printf("\n========================================\n");

  // Ethernet
  printf("[Ethernet]\n");
  printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0],
         eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3],
         eth->ether_shost[4], eth->ether_shost[5]);
  printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0],
         eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3],
         eth->ether_dhost[4], eth->ether_dhost[5]);

  // IP
  printf("[IP]\n");
  printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
  printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

  // TCP
  printf("[TCP]\n");
  printf("  Src Port: %d\n", ntohs(tcp->tcp_sport)); // 네트워크 바이트 오더 변환
  printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

  // payload 있을 때만 출력 (빈 ACK 패킷 제외)
  if (payload_len > 0) {
    printf("[HTTP Message] (length: %d bytes)\n", payload_len);
    int print_len = (payload_len < 1024) ? payload_len : 1024;
    for (int i = 0; i < print_len; i++) {
      unsigned char c = payload[i];
      if (c == '\r')
        continue;
      putchar((c >= 0x20 && c < 0x7f) || c == '\n' ? c : '.'); // 출력 불가 문자는 . 으로
    }
    if (payload_len > 1024)
      printf("\n... (%d bytes more)\n", payload_len - 1024);
  }

  printf("========================================\n");
  fflush(stdout);
}

// NIC을 열고 BPF 필터(tcp)를 적용한 뒤 패킷 캡처 루프 실행
int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net = 0;

  handle = pcap_open_live("eno1", BUFSIZ, 1, 1000, errbuf); // 1 = promiscuous mode
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live 실패: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "pcap_compile 실패: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  printf("TCP 패킷 캡처 시작 (Ctrl+C로 종료)...\n");

  pcap_loop(handle, -1, got_packet, NULL); // -1 = 무한 캡처

  pcap_close(handle);
  return 0;
}

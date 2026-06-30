## 1. 과제 개요

### 과제 목표

C 언어와 pcap API를 활용하여 네트워크 패킷을 실시간으로 캡처하고, 각 계층의 헤더 정보와 HTTP 메시지를 출력하는 프로그램을 작성한다.

### 출력 요구사항

| 계층 | 출력 내용 |
| --- | --- |
| Ethernet Header | Src MAC / Dst MAC |
| IP Header | Src IP / Dst IP |
| TCP Header | Src Port / Dst Port |
| HTTP Message | Application 계층 payload |

### 제약사항

- TCP 프로토콜만 대상으로 처리 (UDP는 무시)
- IP 헤더, TCP 헤더의 길이 필드를 사용하여 payload 위치 계산

---

## 2. 배경 지식

### 2-1. 네트워크 계층 구조 (OSI 7 Layer)

네트워크 통신은 계층별로 역할이 분리되어 있다. 각 계층은 상위 계층의 데이터에 자신의 헤더를 붙여 하위 계층으로 전달한다.

```
Application  →  HTTP 메시지 (GET / HTTP/1.1 ...)
Transport    →  TCP 헤더 + HTTP 데이터
Network      →  IP 헤더 + TCP 세그먼트
Data Link    →  Ethernet 헤더 + IP 패킷
Physical     →  전선으로 비트 전송
```

### 2-2. 캡슐화(Encapsulation)와 역캡슐화(Decapsulation)

**캡슐화**는 데이터를 보낼 때 각 계층이 헤더를 추가하는 과정이다.

```
[HTTP Data]
↓ TCP 헤더 추가
[TCP Header | HTTP Data]
↓ IP 헤더 추가
[IP Header | TCP Header | HTTP Data]
↓ Ethernet 헤더 추가
[Eth Header | IP Header | TCP Header | HTTP Data]  →  전송
```

**역캡슐화**는 수신 측에서 각 계층의 헤더를 순서대로 벗겨내며 데이터를 꺼내는 과정이다. 이번 과제가 바로 역캡슐화 과정을 직접 구현하는 것이다.

### 2-3. pcap 라이브러리

pcap(Packet Capture)은 네트워크 인터페이스(NIC)를 지나는 패킷을 OS 커널 레벨에서 가로채어 사용자 프로그램에 전달해주는 라이브러리다.

```
인터넷 → NIC → 커널 네트워크 스택
                      │
                 pcap이 여기서 복사본을 캡처
                      │
              사용자 프로그램 (got_packet 호출)
```

raw socket 접근을 사용하기 때문에 실행 시 root 권한(sudo)이 필요하다.

### 2-4. libpcap의 동작 과정

이번 프로그램은 libpcap API를 이용하여 다음과 같은 순서로 패킷을 수집한다.

```
pcap_open_live()
        │
        ▼
네트워크 인터페이스(NIC) 열기
        │
        ▼
pcap_compile()
        │
BPF 필터 컴파일 ("tcp")
        │
        ▼
pcap_setfilter()
        │
커널에 필터 적용
        │
        ▼
pcap_loop()
        │
패킷 수신 시마다
        ▼
got_packet() 호출
```

각 함수의 역할은 다음과 같다.

| 함수 | 역할 |
| --- | --- |
| pcap_open_live | NIC를 열고 패킷 캡처 시작 |
| pcap_compile | BPF 필터를 컴파일 |
| pcap_setfilter | 필터를 커널에 적용 |
| pcap_loop | 패킷이 들어올 때마다 콜백 함수 호출 |
| got_packet | 실제 패킷을 분석하는 함수 |

---

## 3. 패킷 메모리 구조

pcap이 넘겨주는 `packet` 포인터는 Ethernet 프레임의 첫 바이트부터 시작하는 연속된 메모리다. 각 헤더는 이전 헤더 바로 뒤에 위치한다.

```
packet[0]
│
├── [Ethernet Header]  14바이트 (고정)
│        ether_dhost[6] + ether_shost[6] + ether_type[2]
│
├── [IP Header]  iph_ihl × 4 바이트 (가변, 보통 20)
│        ihl(4비트) + ver(4비트) + TOS + 전체길이 + ...
│
├── [TCP Header]  TH_OFF(tcp) × 4 바이트 (가변, 보통 20)
│        sport + dport + seq + ack + data offset + flags + ...
│
└── [HTTP Payload]  나머지 전부
```

헤더 길이가 가변인 이유는 IP 헤더와 TCP 헤더 모두 **Options 필드**를 포함할 수 있기 때문이다. Options가 없으면 20바이트, 있으면 최대 60바이트까지 늘어난다.

---

## 4. 핵심 로직 분석

### 4-1. IP 헤더 길이 계산

IP 헤더의 `iph_ihl` 필드는 4비트로, "4바이트 단위 덩어리가 몇 개인가"를 나타낸다.

```c
int ip_header_len = ip->iph_ihl * 4;
```

- `iph_ihl = 5` → `5 × 4 = 20바이트` (Options 없는 기본 헤더)
- `iph_ihl = 6` → `6 × 4 = 24바이트` (Options 4바이트 포함)

이 값을 계산하지 않고 무조건 20을 더하면, Options가 포함된 패킷에서 TCP 헤더 위치를 잘못 찾게 된다.

### 4-2. TCP 헤더 길이 계산

TCP 헤더의 Data Offset 필드도 동일한 원리다. `tcp_offx2` 필드의 상위 4비트가 헤더 길이를 나타낸다. `TH_OFF` 매크로가 이를 추출한다.

```c
// myheader.h의 매크로 정의
#define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)

// 사용
int tcp_header_len = TH_OFF(tcp) * 4;
```

`0xf0`과 AND 연산으로 하위 4비트를 제거하고, `>> 4`로 오른쪽으로 밀어 실제 값을 추출한다.

### 4-3. HTTP payload 위치와 길이

```c
// payload 시작 위치
const u_char *payload = packet
    + sizeof(struct ethheader)   // Ethernet: 14바이트
    + ip_header_len              // IP: 가변
    + tcp_header_len;            // TCP: 가변

// payload 길이
// iph_len = IP 패킷 전체 길이 (IP 헤더 + TCP 헤더 + 데이터)
int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
```

`ntohs()`를 사용하는 이유: 네트워크 프로토콜은 빅엔디안(Big-endian) 바이트 오더를 사용하는데, x86 CPU는 리틀엔디안(Little-endian)이다. `ntohs()`가 이 변환을 처리해준다.

### 4-4. BPF 필터

```c
char filter_exp[] = "tcp";
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
```

BPF(Berkeley Packet Filter)는 커널 레벨에서 동작하는 필터다. "tcp"로 설정하면 TCP 패킷만 사용자 프로그램으로 올라오고 UDP, ICMP 등은 커널에서 이미 차단된다. 사용자 코드에서 일일이 걸러내는 것보다 훨씬 효율적이다.

### 4-5. Promiscuous Mode

```c
handle = pcap_open_live("eno1", BUFSIZ, 1, 1000, errbuf);
//                                       ↑
//                              1 = promiscuous mode ON
```

일반 모드에서 NIC은 자신의 MAC 주소로 오는 패킷만 수신한다. Promiscuous mode를 켜면 네트워크를 지나는 모든 패킷을 캡처할 수 있다.

### 4-6. 바이트 오더 변환 (ntohs의 필요성)

네트워크 프로토콜은 데이터를 전송할 때 **빅 엔디안(Big-endian, Network Byte Order)** 방식을 사용하지만, 우리가 사용하는 x86 계열의 CPU는 메모리에 데이터를 저장할 때 **리틀 엔디안(Little-endian, Host Byte Order)** 방식을 사용한다.

예를 들어 HTTP 기본 포트인 `80`은 16진수로 `0x0050`이다.

- **네트워크 전송 (빅 엔디안):** `00`을 먼저, `50`을 나중에 보낸다. (`[00][50]`)
- **CPU 수신 (리틀 엔디안):** 들어온 순서대로 메모리에 `[00][50]`으로 저장한 뒤, 이를 16비트 정수로 읽어들일 때 역순으로 조합하여 `0x5000` (십진수 20480)으로 잘못 해석하게 된다.

따라서 2바이트 이상인 데이터(포트 번호나 패킷 전체 길이 `iph_len`)를 CPU가 올바르게 읽기 위해서는 반드시 `ntohs()` (Network to Host Short) 함수를 사용하여 바이트 순서를 뒤집어주어야 한다. (MAC 주소의 경우 1바이트 크기의 배열 요소 단위로 순차 접근하므로 변환이 필요하지 않다.)

---

## 5. 코드

보고서 최하단에 추가로 Github 링크도 추가해놓았다.

### myheader.h

```c
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,
                     iph_ver:4;
  unsigned char      iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  unsigned short int iph_flag:3,
                     iph_offset:13;
  unsigned char      iph_ttl;
  unsigned char      iph_protocol;
  unsigned short int iph_chksum;
  struct  in_addr    iph_sourceip;
  struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};
```

### pcap_sniffer.c

```c
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
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) != 0x0800) // 0x0800 = IPv4
    return;

  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  int ip_header_len = ip->iph_ihl * 4; // ihl * 4 = 실제 바이트 수

  if (ip->iph_protocol != IPPROTO_TCP)
    return;

  struct tcpheader *tcp =
      (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
  int tcp_header_len = TH_OFF(tcp) * 4; // data offset 상위 4비트 * 4

  int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
  const u_char *payload =
      packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;

  printf("\n========================================\n");

  printf("[Ethernet]\n");
  printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  printf("[IP]\n");
  printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
  printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

  printf("[TCP]\n");
  printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
  printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

  if (payload_len > 0) {
    printf("[HTTP Message] (length: %d bytes)\n", payload_len);
    int print_len = (payload_len < 1024) ? payload_len : 1024;
    for (int i = 0; i < print_len; i++) {
      unsigned char c = payload[i];
      if (c == '\r') continue;
      putchar((c >= 0x20 && c < 0x7f) || c == '\n' ? c : '.');
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
```

---

## 6. 빌드 및 실행

### 빌드

```bash
gcc -o pcap_sniffer pcap_sniffer.c -lpcap
```

- `lpcap` 플래그로 libpcap 공유 라이브러리를 링크한다. 이 옵션 없이 컴파일하면 `pcap_open_live` 등의 함수를 찾지 못해 링커 에러가 발생한다.

### 실행

```bash
sudo ./pcap_sniffer
```

### 테스트

다른 터미널에서 HTTP 요청을 발생시킨다.

```bash
curl <http://httpforever.com>
```

> HTTPS(포트 443)는 TLS로 암호화되어 있어 payload 내용을 볼 수 없다. 반드시 `http://` 사이트로 테스트해야 한다.
> 

---

## 7. 실행 결과

`curl <http://httpforever.com`> 실행 시 캡처된 출력:

```
========================================
[Ethernet]
  Src MAC : 70:85:c2:cd:4c:67
  Dst MAC : b0:38:6c:48:0c:47
[IP]
  Src IP  : 192.168.0.2
  Dst IP  : 146.190.62.39
[TCP]
  Src Port: 47468
  Dst Port: 80
[HTTP Message] (length: 79 bytes)
GET / HTTP/1.1
Host: httpforever.com
User-Agent: curl/8.20.0
Accept: */*

========================================

========================================
[Ethernet]
  Src MAC : b0:38:6c:48:0c:47
  Dst MAC : 70:85:c2:cd:4c:67
[IP]
  Src IP  : 146.190.62.39
  Dst IP  : 192.168.0.2
[TCP]
  Src Port: 80
  Dst Port: 47468
[HTTP Message] (length: 1448 bytes)
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 30 Jun 2026 15:22:30 GMT
Content-Type: text/html
...
<html>
<body>
  <h2>HTTP FOREVER</h2>
</body>
</html>
========================================
```

Src Port 47468 → Dst Port 80 패킷은 클라이언트(내 PC)가 서버로 보낸 HTTP Request이고,
Src Port 80 → Dst Port 47468 패킷은 서버가 응답한 HTTP Response다.

---

## 8. 느낀 점 및 이해

이번 과제를 통해 네트워크 패킷이 실제로 어떤 구조로 되어 있는지 직접 확인할 수 있었다. 수업에서 배운 OSI 7계층 모델이 실제로 바이트 단위로 구현되어 있다는 것을 코드로 체감했다.

특히 IP 헤더와 TCP 헤더의 길이가 고정이 아니라 가변이라는 점이 인상적이었다. `iph_ihl * 4`, `TH_OFF(tcp) * 4`처럼 각 헤더에 담긴 길이 정보를 읽어서 다음 계층의 시작 위치를 계산해야 한다는 것을 직접 구현하며 이해하게 됐다.

또한 HTTPS 트래픽은 TLS 암호화로 인해 payload를 볼 수 없었는데, 이를 통해 암호화가 실제 보안에서 얼마나 중요한 역할을 하는지 실감했다.

---

## 9. GitHub

https://github.com/cindysjlee/whs-pcap-programming
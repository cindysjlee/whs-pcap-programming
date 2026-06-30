# PCAP Programming 과제 보고서

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

## 5. 빌드 및 실행

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
curl http://httpforever.com
```

> HTTPS(포트 443)는 TLS로 암호화되어 있어 payload 내용을 볼 수 없다. 반드시 `http://` 사이트로 테스트해야 한다.
> 

---

## 6. 실행 결과

`curl http://httpforever.com` 실행 시 캡처된 출력:

```
========================================
[Ethernet]
  Src MAC : 70:85:c2:cd:4c:67
  Dst MAC : b0:38:6c:48:0c:47
[IP]
  Src IP  : 192.168.0.2
  Dst IP  : 146.190.62.39
[TCP]
  Src Port: 35490
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
  Dst Port: 35490
[HTTP Message] (length: 1448 bytes)
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 30 Jun 2026 19:54:19 GMT
Content-Type: text/html
Content-Length: 5124
Last-Modified: Wed, 22 Mar 2023 14:54:48 GMT
Connection: keep-alive
ETag: "641b16b8-1404"
Referrer-Policy: strict-origin-when-cross-origin
X-Content-Type-Options: nosniff
Feature-Policy: accelerometer 'none'; camera 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'
Content-Security-Policy: default-src 'self'; script-src cdnjs.cloudflare.com 'self' 'report-sha256'; style-src cdnjs.cloudflare.com 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.googleapis.com fonts.gstatic.com cdnjs.cloudflare.com; frame-ancestors 'none'; report-uri https://scotthelme.report-uri.com/r/d/csp/enforce
Accept-Ranges: bytes

<!DOCTYPE HTML>
<html>
.<head>
..<title>HTTP Forever</title>
..<meta http-equiv="content-type" content="text/html; charset=utf-8" />
..<meta name="description" content="A site that will always be
... (424 bytes more)
========================================
```

- `Src Port 35490 → Dst Port 80` 패킷은 클라이언트(내 PC)가 서버로 보낸 **HTTP GET Request**이다.
- `Src Port 80 → Dst Port 35490` 패킷은 서버가 응답한 **HTTP 200 OK Response**이며, Payload로 HTML 문서가 전달된 것을 확인할 수 있다.

---

## 7. 느낀 점 및 이해

#### 1. 이론적 모델의 실체화 (OSI 7 Layer와 포인터 연산)

기존에는 OSI 7계층이나 캡슐화/역캡슐화 과정을 주로 다이어그램이나 이론적인 개념으로만 알고 있었습니다. 하지만 이번 과제를 통해 C 언어의 구조체 포인터 형변환과 메모리 오프셋 연산을 활용하여, 캡처된 패킷의 원시 데이터에 직접 접근해 바깥쪽 헤더부터 하나씩 벗겨내는 과정을 구현해 보면서 네트워크 모델이 실제 바이트 단위로 어떻게 구현되어 있는지 체감할 수 있었습니다.

#### **2. 동적 오프셋 계산의 중요성 (가변 헤더)**

가장 인상 깊었던 부분은 IP 헤더와 TCP 헤더의 길이가 고정되어 있지 않다는 점이었습니다. 단순히 고정된 크기만큼 메모리를 이동시키는 것이 아니라, `iph_ihl * 4`나 `TH_OFF(tcp) * 4`처럼 패킷 내부의 제어 정보를 동적으로 읽어와 다음 계층의 정확한 시작 위치를 스스로 계산하도록 프로그래밍해야 한다는 점을 깨달았습니다. 이를 통해 프로토콜 설계자들이 확장성(Options 필드)을 어떻게 고려했는지 이해할 수 있었습니다.

#### **3. 시스템 아키텍처와 네트워크의 차이 이해 (엔디안)**

또한, 바이트 오더의 차이를 처리하는 과정도 흥미로웠습니다. 호스트 시스템(Little-endian)과 네트워크 표준(Big-endian)의 차이로 인해 2바이트 이상의 데이터(포트 번호, 패킷 길이 등)를 읽을 때 데이터가 왜곡되는 현상을 겪으면서, 이기종 시스템 간의 통신에서 `ntohs()`와 같은 바이트 순서 변환이 왜 필수적인지 코드 레벨에서 명확히 이해하게 되었습니다.

#### **4. 평문 통신의 취약성과 TLS 암호화의 위력**

보안적인 측면에서도 큰 깨달음을 얻었습니다. `curl`을 이용해 평문(HTTP)으로 통신했을 때는 패킷 캡처를 통해 주고받는 HTML 문서나 헤더 정보(Payload)가 날것 그대로 노출되는 것을 확인했습니다. 반면, HTTPS 트래픽을 캡처했을 때는 TLS 암호화가 적용되어 Payload 부분이 완전히 해독 불가능한 바이트 덩어리로 출력되었습니다. 이를 통해 왜 현대 웹 환경에서 평문 통신을 지양하고 HTTPS를 필수로 도입해야 하는지, 통신 암호화가 스니핑(Sniffing) 공격을 방어하는 데 얼마나 강력한 역할을 하는지 직접 눈으로 확인할 수 있었습니다.

#### **5. 실무적 관점에서의 한계 및 개선 방향**

이번 과제는 정상적인 패킷 캡처에 집중하여 구현했지만, 코드를 작성하며 "만약 조작되거나 손상된 짧은 패킷이 들어온다면?"이라는 의문을 갖게 되었습니다. 길이 검증 없이 메모리 포인터만 이동시킬 경우 Segmentation Fault가 발생할 수 있음을 인지하게 되었고, 실제 상용 보안 장비나 분석 툴을 개발할 때는 캡처된 버퍼의 길이(`caplen`)를 엄격하게 검사하는 예외 처리와 메모리 안전성이 반드시 동반되어야 함을 배울 수 있는 뜻깊은 경험이었습니다.

---

## 8. GitHub

https://github.com/cindysjlee/whs-pcap-programming
# PCAP Programming

pcap API를 사용해 네트워크 패킷을 캡처하고, 각 계층의 헤더 정보와 HTTP 메시지를 출력하는 C 프로그램입니다.

## 출력 정보

- **Ethernet Header**: Src MAC / Dst MAC
- **IP Header**: Src IP / Dst IP
- **TCP Header**: Src Port / Dst Port
- **HTTP Message**: Application 계층 payload (TCP만 대상)

## 파일 구성

| 파일 | 설명 |
|------|------|
| `pcap_sniffer.c` | 메인 구현 파일 |
| `myheader.h` | Ethernet / IP / TCP 헤더 구조체 정의 |

## 빌드

```bash
gcc -o pcap_sniffer pcap_sniffer.c -lpcap
```

## 실행

```bash
sudo ./pcap_sniffer
```

> raw socket 접근이 필요하기 때문에 `sudo` 필수

## 테스트

다른 터미널에서 HTTP 요청을 보내면 캡처됩니다.

```bash
curl http://httpforever.com
```

> HTTPS(443 포트)는 TLS로 암호화되어 있어 payload 내용을 볼 수 없으므로, `http://` 사이트로 테스트해야 합니다.

## 실행 예시

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
```

## 참고

- 네트워크 인터페이스명은 환경에 따라 다를 수 있습니다. (`ip link show` 로 확인)
- `pcap_sniffer.c` 내 `pcap_open_live()` 첫 번째 인자를 본인 환경에 맞게 수정하세요.

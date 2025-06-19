# MQTT 취약점 공격 및 방어 Plugin 제작

## 프로젝트 개요

개발 프로젝트 "MQTT 취약점 공격 및 방어 plugin 제작"은 Mosquitto 바이딩 위한 플랫폼에서 MQTT 코스 취약점을 사용자 등록, 통신, 통식 지시로 공격하고 간단한 플러그인으로 방어할 수 있도록 만든 **MQTT 프로토콜 공격/방어 시뮬레이션** 이다.

## 도움 가능 목적

* MQTT TLS의 사용 경로에서 취약점을 공격
* topic brute force / password brute force / buffer overflow 및 DoS 공격 결과 시험
* 공격과 방어가 각 방향성을 가진 두 개의 port ( 8883: plugin 적용 / 8884: base TLS only)
* 대입 공격 UI 등은 Flutter를 통해 간단 방면으로 공격 방어 시험

---

## 그래프 개요

```
FinalProject/
├ Makefile
├ mosq-auth-lockout/
│ └ auth_lockout_ip.c         # IP 기본 login 신뢰 오류 목록과 delay logic
├ mosq-dos-protecter/
│ └ auth_dos_protection.c     # 매 회신등에 대한 모듈과 무거리 제어
├ mosq-topic-counter/
│ └ auth_topic_bruteforce.c   # topic에 user/pass/timestamp 형식으로 replay 방지
└ certs.crt                       # TLS 인증서 (ca.crt, mosquitto.crt, etc.)

```

---

## 방어 Plugin 설명

### 1. IP Lockout Plugin (`mosq-auth-lockout`)

* 다음 포트에서 가지 추적:

  * 잘못된 로그인 시도 5회 이상 시 IP별 딜레이 부과
  * shadow password 사용 (서버 계정 기반 로그인)
  * connection rate limit까지 포함 가능 (60초 내 60회 이상 차단)

### 2. DoS Protection Plugin (`mosq-dos-protecter`)

* publish message 크기가 너무 크거나 (1MB 이상)
* 초당 publish 횟수가 너무 많은 클라이언트 차단
* 기본값: 초당 10개 메시지, 최대 1MB

### 3. Topic-Based Replay 방지 (`mosq-topic-counter`)

* publish할 때 `username/password/timestamp/실제topic` 구조 사용
* timestamp 검증을 통해 일정 시간 내만 허용됨 (ex: 10초)
* 재전송 replay 공격 시도 시 payload는 discard

---

## 데모 시나리오 구성 예시

| 단계 | 포트   | 기능         | 설명                                               |
| -- | ---- | ---------- | ------------------------------------------------ |
| 1  | 8884 | TLS-only   | 기본 로그인 기능만 적용된 브로커 (인증서로만 보호)                    |
| 2  | 8883 | Plugin 활성화 | 위 3가지 plugin 모두 적용 (brute force, replay, DoS 보호) |

---

## 설치 방법

```bash
# 모든 plugin 빌드
make

# 설치 (default: /etc/mosquitto/plugins)
sudo make install

# mosquitto 실행
mosquitto -c mosquitto_tls_plugins.conf -v
```

---

## 관련 기술

* MQTT 5.0 Plugin API
* TLS 인증서, shadow password 인증
* uthash, pthread 기반 thread-safe plugin

---



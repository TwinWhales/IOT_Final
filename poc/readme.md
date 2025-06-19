# MQTT Token-based Topic Authentication Demo

이 프로젝트는 TLS 기반 MQTT 브로커에서 **Mosquitto 플러그인(auth-lockout-ip 및 token-topic)** 구조를 활용하여 2단계 인증을 적용한 메시지 전송 방식을 시연합니다.

## 목적

- MQTT 브로커에 연결할 때는 **`/etc/shadow` 기반 사용자 인증** (auth-lockout-ip plugin)을 사용하고,  
- 실제 메시지를 전송할 때는 **주제(topic) 경로 내에 사용자명/비밀번호/타임스탬프를 포함**하는 방식을 사용하여 **추가적인 권한 검사를 수행**합니다.  
- 이 구조는 `token-topic` 플러그인이 동작하는 MQTT 브로커(예: `8883` 포트)에서 실습됩니다.

---

## 구조 요약

```
                    ┌─────────────┐
                    │  사용자 A   │
                    └────┬────────┘
                         │ MQTT TLS 연결
               [auth-lockout-ip 플러그인]
                         ▼
                Mosquitto 인증 (user/pass)
                         │
              ┌──────────┴────────────┐
              ▼                       ▼
      연결 성공                인증 실패: delay 증가
                         │
                  ┌──────┴──────┐
                  ▼             ▼
     MQTT 메시지 전송 (topic 경로에 user/pass/timestamp 포함)
                  │
        [token-topic 플러그인에서 토픽 인증]
                  ▼
       Publish 허용 or ACL DENIED + 재전송 가능
```

---

## 주요 구성 요소

| 변수명 | 설명 |
|--------|------|
| `BROKER_IP` | 브로커의 IP 주소 |
| `BROKER_PORT` | TLS 기반 브로커 포트 (8883 등) |
| `CA_CERT_PATH` | TLS 인증을 위한 `ca.crt` 경로 |
| `CONNECTION_USERNAME` / `CONNECTION_PASSWORD` | 기본 연결을 위한 사용자명 (auth-lockout-ip 플러그인 기준) |
| `TOPIC_USERNAME` / `TOPIC_PASSWORD` | 토픽 기반 인증을 위한 사용자명 (token-topic 플러그인 기준) |
| `REAL_TOPIC_TO_PUBLISH` | 실제 명령이 도달해야 할 주제 (ex. `cmd/lock/open`) |
| `TOPIC_TO_SUBSCRIBE` | 상태 응답을 받기 위한 주제 (ex. `status/lock/open`) |

---

## 실행 예시

```bash
python token_publish.py
```

출력 예시:

```
 Successfully connected to the broker as 'kali'.
   Subscribing to topic: status/lock/open

--- Publishing Command (with different topic credentials) ---
   Real Topic:      cmd/lock/open
   Payload:         open
   Plugin Topic:    user1/asdf1234/1729432347/cmd/lock/open
----------------------------------------------------------

[수신] status/lock/open → open
```

---

## 주의사항

- 반드시 브로커는 TLS (SSL)로 구성되어 있어야 하며 `token-topic` 플러그인은 **클라이언트의 메시지를 인터셉트**하여 인증 검증 후 재전송합니다.
- CA 인증서(`ca.crt`)는 클라이언트가 MQTT 브로커의 인증서를 검증할 수 있도록 필요합니다.

---

## 관련 플러그인 설명

### 1. `auth-lockout-ip`
- `/etc/shadow` 기반 인증.
- 로그인 실패 시 IP 기준으로 점진적 지연(`delay`) 적용.
- DoS 완화용 `connection rate limit` 포함.

### 2. `token-topic`
- 메시지 토픽 형식:  
  ```
  username/password/timestamp/actual/topic
  ```
- 타임스탬프 기반 리플레이 방지.
- `/etc/shadow` 인증 기반 캐시 사용.

---

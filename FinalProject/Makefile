CC      = gcc
CFLAGS  = -fPIC -shared -Wall -Werror -D_GNU_SOURCE
LDFLAGS = -lpthread -lcrypt

# Mosquitto paths - 환경에 맞게 수정하세요.
INCLUDES = -I/usr/include/mosquitto
PLUGIN_DIR = /etc/mosquitto/plugins
SUDO = sudo

# --- 디렉토리 및 소스/타겟 정의 ---
# 1. 각 플러그인의 디렉토리 이름
DIR_LOCKOUT = mosq-auth-lockout
DIR_DOS     = mosq-dos-protecter
DIR_TOPIC   = mosq-topic-counter

# 2. 각 디렉토리 안의 실제 C 소스 파일 이름 (★★ 중요 ★★)
#    만약 실제 파일 이름이 다르다면 이 부분을 수정하세요.
SRC_FILE_LOCKOUT = auth_lockout_ip.c
SRC_FILE_DOS     = auth_dos_protection.c
SRC_FILE_TOPIC   = auth_topic_bruteforce.c # 이 파일 이름은 실제 파일에 맞게 수정이 필요할 수 있습니다.

# 3. 최종 소스 파일 경로 및 빌드 타겟
SRC_LOCKOUT = $(DIR_LOCKOUT)/$(SRC_FILE_LOCKOUT)
SRC_DOS     = $(DIR_DOS)/$(SRC_FILE_DOS)
SRC_TOPIC   = $(DIR_TOPIC)/$(SRC_FILE_TOPIC)

TARGET_LOCKOUT = $(DIR_LOCKOUT).so
TARGET_DOS     = $(DIR_DOS).so
TARGET_TOPIC   = $(DIR_TOPIC).so

TARGETS = $(TARGET_LOCKOUT) $(TARGET_DOS) $(TARGET_TOPIC)

# --- 메인 타겟 ---
.PHONY: all clean install

all: $(TARGETS)
	@echo "모든 플러그인이 성공적으로 빌드되었습니다."

install: all
	@if [ ! -d "$(PLUGIN_DIR)" ]; then \
		echo "플러그인 디렉토리 $(PLUGIN_DIR)를 찾을 수 없어 새로 생성합니다..."; \
		$(SUDO) mkdir -p $(PLUGIN_DIR); \
	fi
	$(SUDO) cp $(TARGETS) $(PLUGIN_DIR)
	@echo "모든 플러그인이 $(PLUGIN_DIR)에 설치되었습니다."

clean:
	rm -f $(TARGETS) *.o
	@echo "모든 빌드 결과물을 삭제했습니다."

# --- 개별 빌드 규칙 ---
$(TARGET_LOCKOUT): $(SRC_LOCKOUT)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(TARGET_DOS): $(SRC_DOS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(TARGET_TOPIC): $(SRC_TOPIC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# --- 개별 설치 및 정리 규칙 ---
.PHONY: install-lockout install-dos install-topic clean-lockout clean-dos clean-topic

install-lockout: $(TARGET_LOCKOUT)
	$(SUDO) cp $< $(PLUGIN_DIR)
	@echo "$< 가 $(PLUGIN_DIR) 에 설치되었습니다."

install-dos: $(TARGET_DOS)
	$(SUDO) cp $< $(PLUGIN_DIR)
	@echo "$< 가 $(PLUGIN_DIR) 에 설치되었습니다."

install-topic: $(TARGET_TOPIC)
	$(SUDO) cp $< $(PLUGIN_DIR)
	@echo "$< 가 $(PLUGIN_DIR) 에 설치되었습니다."

clean-lockout:
	rm -f $(TARGET_LOCKOUT)
	@echo "$(TARGET_LOCKOUT) 가 삭제되었습니다."

clean-dos:
	rm -f $(TARGET_DOS)
	@echo "$(TARGET_DOS) 가 삭제되었습니다."

clean-topic:
	rm -f $(TARGET_TOPIC)
	@echo "$(TARGET_TOPIC) 가 삭제되었습니다."
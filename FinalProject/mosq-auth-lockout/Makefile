CC      = gcc
CFLAGS  = -fPIC -shared -Wall
LDFLAGS = -lpthread

# Mosquitto 설치 경로
INCLUDES = -I/usr/include/mosquitto

TARGET  = auth_topic_bruteforce.so
SOURCES = auth_topic_bruteforce.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean

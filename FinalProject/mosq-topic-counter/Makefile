CC      = gcc
CFLAGS  = -fPIC -shared -Wall -Werror -D_GNU_SOURCE
LDFLAGS = -lpthread -lcrypt

# Mosquitto paths
INCLUDES = -I/usr/include/mosquitto
PLUGIN_DIR = /etc/mosquitto/plugins
SUDO = sudo

# Target
TARGET  = auth_topic_bruteforce.so
SOURCES = auth_topic_bruteforce.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)
	@echo "Successfully built $(TARGET)"

install: $(TARGET)
	@if [ ! -d "$(PLUGIN_DIR)" ]; then \
		echo "Plugin directory $(PLUGIN_DIR) not found. Creating it..."; \
		$(SUDO) mkdir -p $(PLUGIN_DIR); \
	fi
	$(SUDO) cp $(TARGET) $(PLUGIN_DIR)
	@echo "Plugin $(TARGET) installed to $(PLUGIN_DIR)"

clean:
	rm -f $(TARGET)
	@echo "Cleaned up build artifacts."
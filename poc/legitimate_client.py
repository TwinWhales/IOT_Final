{{ ... }}
# --- Configuration ---
BROKER_IP = "192.168.0.13"      # Your MQTT Broker IP
BROKER_PORT = 8883              # MQTT Broker Port (TLS)
CA_CERT_PATH = "ca.crt"         # Path to the CA Certificate

# === Layer 1: Connection Credentials (for auth-lockout-ip plugin using /etc/shadow) ===
# These credentials are for establishing the initial connection to the broker.
CONNECTION_USERNAME = "kali"
CONNECTION_PASSWORD = "kali"

# === Layer 2: Topic Credentials (for token-topic plugin using its own passwd file) ===
# These credentials are embedded in the topic string to authorize the publish action.
TOPIC_USERNAME = "user1"
TOPIC_PASSWORD = "asdf1234"

# The actual command topic and payload to send
REAL_TOPIC_TO_PUBLISH = "cmd/lock/open"
PAYLOAD = "open"

# The topic to listen for the response on
TOPIC_TO_SUBSCRIBE = "status/lock/open"
# --- End of Configuration ---

# This callback is executed when a message is received from the broker.
{{ ... }}
    if rc == 0:
        print(f"✅ Successfully connected to the broker as '{CONNECTION_USERNAME}'.")
        
        # 1. Subscribe to the status topic to receive the response
        print(f"   Subscribing to topic: {TOPIC_TO_SUBSCRIBE}")
        client.subscribe(TOPIC_TO_SUBSCRIBE)
        
        # 2. Construct the special topic for the token-topic plugin
        timestamp = int(time.time())
        plugin_compliant_topic = f"{TOPIC_USERNAME}/{TOPIC_PASSWORD}/{timestamp}/{REAL_TOPIC_TO_PUBLISH}"
        
        print("\n--- Publishing Command (with different topic credentials) ---")
        print(f"   Real Topic:      {REAL_TOPIC_TO_PUBLISH}")
        print(f"   Payload:         {PAYLOAD}")
        print(f"   Plugin Topic:    {plugin_compliant_topic}")
        print("----------------------------------------------------------\n")
        
        # 3. Publish the message
        client.publish(plugin_compliant_topic, payload=PAYLOAD, qos=1)
{{ ... }}
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"legit-client-{int(time.time())}")
    client.on_connect = on_connect
    client.on_message = on_message

    client.username_pw_set(CONNECTION_USERNAME, CONNECTION_PASSWORD)
    
    if not os.path.exists(CA_CERT_PATH):
        print(f"❌ Error: CA certificate not found at '{CA_CERT_PATH}'")
{{ ... }}

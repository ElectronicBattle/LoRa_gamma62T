// DFRobot FireBeetle 2 ESP32-E (DFR0654) - IoT Gate Alert System
// Final Stable Version: Secure TLS, Non-Blocking, and Persistent Logging.
// UPDATED DEC 2025: Core 3.x Resilience & Multi-Source NTP

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <string.h>  
#include <secrets.h> 
#include <ctype.h>   
#include "esp_task_wdt.h" 
#include "esp_log.h" 
#include "FS.h"
#include "LittleFS.h" 
#include <WebServer.h> 

// --- FIX: ADD FUNCTION PROTOTYPES FOR LINKER ERROR ---
void setup();
void loop();
void reconnectMQTT();
void checkAndReconnectNetwork();
void initBlink(int sourcePin, int sinkPin); 
void blinkHandler();                         
void urlEncode(const char* input, char* output, size_t outputSize);
bool serialReadHandler(); 
void sendPushover();     
void logToLittleFS(const char* eventMessage);
void checkAndRotateLog();
void initWebServer();

// --- HARDWARE & SERIAL CONFIGURATION ---
#define WDT_TIMEOUT_SEC 5  
#define BATT_LOW_THRESHOLD_V 2.00
#define BUTTON_PIN 27 
#define SENSOR_PIN 4   
#define LED_DRIVER_A 16 
#define LED_DRIVER_B 14  
const unsigned long FLASH_DURATION_MS = 100;  
#define SERIAL_RX_PIN 25  
#define SERIAL_TX_PIN 17  
#define BAUD_RATE 19200
#define PACKET_SIZE 10
byte packet_buffer[PACKET_SIZE] = { 0 };
#define PACKET_CR 0x0D  
#define PACKET_LF 0x0A  

const char* LOG_FILE = "/events.log";
const char* LOG_OLD_FILE = "/events.old"; 
#define LOG_MESSAGE_SIZE 128
#define MAX_LOG_SIZE_KB 500 

#define TIMESTAMP_SIZE 16   
#define STATUS_SIZE 10      
#define MESSAGE_BUF_SIZE 150 
#define POSTDATA_BUF_SIZE 512 
#define URL_BUF_SIZE 64     

// --- GLOBAL OBJECTS ---
WiFiClient espClient;
WiFiClientSecure secureClient;
PubSubClient mqttClient(espClient);
WebServer server(80); 

// --- NETWORK RESILIENCE VARIABLES ---
const unsigned long RECONNECT_INTERVAL_MS = 5000; 
unsigned long last_reconnect_attempt_ms = 0;
bool is_online_mode = false; 

// NEW: 30s Grace Period variables
unsigned long last_wifi_ok_ms = 0;
const unsigned long WIFI_GRACE_PERIOD_MS = 30000;

// NEW: NTP Force Sync Timer
unsigned long last_ntp_sync_attempt_ms = 0;
const unsigned long NTP_RETRY_INTERVAL_MS = 30000;

const int MAX_RECONNECT_FAILURES = 10;
int reconnect_fail_count = 0; 

volatile unsigned long blink_stop_time_ms = 0; 
volatile int blink_source_pin = -1;             
volatile int blink_sink_pin = -1;              

volatile bool packet_ready = false;  
volatile size_t packet_index = 0;    
const unsigned long SERIAL_TIMEOUT_MS = 500; 
unsigned long packet_start_time = 0; 

struct Event {
  char status[STATUS_SIZE];
  char source[STATUS_SIZE];
};

#define MAX_QUEUE_SIZE 5 
volatile Event event_queue[MAX_QUEUE_SIZE];
volatile int queue_head = 0;
volatile int queue_tail = 0;
volatile int isr_button_state = HIGH;
volatile int isr_sensor_state = HIGH;
volatile unsigned long last_interrupt_time = 0;
const unsigned long DEBOUNCE_DELAY_MS = 25;

struct GateData {
  char timestamp[TIMESTAMP_SIZE]; 
  char status[STATUS_SIZE];       
  float rssi_dbm = 0.0;
  float batt_voltage = 0.0;
  bool batt_ok = false;
  bool data_valid = false;
} current_data;

// --- INTERRUPT HANDLER (Unchanged) ---
void IRAM_ATTR handleGateInterrupt() {
  unsigned long interrupt_time = millis();
  int current_btn = digitalRead(BUTTON_PIN);
  int current_sensor = digitalRead(SENSOR_PIN);
  if (interrupt_time - last_interrupt_time > DEBOUNCE_DELAY_MS) {
    bool btn_changed = (current_btn != isr_button_state);
    bool sensor_changed = (current_sensor != isr_sensor_state);
    if (btn_changed || sensor_changed) {
      if (((queue_head + 1) % MAX_QUEUE_SIZE) != queue_tail) {
        const char* new_status;
        const char* new_source;
        if (sensor_changed) {
          new_status = (current_sensor == LOW) ? "OPEN" : "CLOSED";
          new_source = "SENSOR";
        } else if (btn_changed) {
          new_status = (current_btn == LOW) ? "CLOSED" : "OPEN";
          new_source = "BUTTON";
        }
        volatile Event* current_event = &event_queue[queue_head];
        strncpy((char*)current_event->status, new_status, STATUS_SIZE - 1);
        current_event->status[STATUS_SIZE - 1] = '\0'; 
        strncpy((char*)current_event->source, new_source, STATUS_SIZE - 1);
        current_event->source[STATUS_SIZE - 1] = '\0';
        queue_head = (queue_head + 1) % MAX_QUEUE_SIZE;
        last_interrupt_time = interrupt_time;
        isr_button_state = current_btn;
        isr_sensor_state = current_sensor;
      }
    }
  }
} 

// --- UTILITIES ---
void urlEncode(const char* input, char* output, size_t outputSize) {
  size_t input_len = strlen(input);
  size_t encoded_index = 0;
  for (size_t i = 0; i < input_len; i++) {
    char c = input[i];
    if (encoded_index >= outputSize - 4) break; 
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') output[encoded_index++] = c;
    else if (c == ' ') output[encoded_index++] = '+';
    else {
      output[encoded_index++] = '%';
      char code1 = (c >> 4) & 0xF;
      char code0 = c & 0xF;
      output[encoded_index++] = (char)((code1 < 10) ? (code1 + '0') : (code1 - 10 + 'A'));
      output[encoded_index++] = (char)((code0 < 10) ? (code0 + '0') : (code0 - 10 + 'A'));
    }
  }
  output[encoded_index] = '\0'; 
}

// RESTORED: Full Gold Narrative for Serial Handler
bool serialReadHandler() {
  if (packet_ready) return true; 
  if (packet_index > 0 && millis() - packet_start_time > SERIAL_TIMEOUT_MS) {
    Serial.printf("Serial Timeout: Packet incomplete after %lu ms. Resetting parser.\n", SERIAL_TIMEOUT_MS);
    while(Serial2.available()) Serial2.read(); 
    packet_index = 0; 
    return false;
  }
  while (Serial2.available() > 0) {
    byte incoming_byte = Serial2.read();
    if (packet_index == 0) packet_start_time = millis(); 
    packet_buffer[packet_index++] = incoming_byte;
    if (packet_index == PACKET_SIZE) {
      if (packet_buffer[PACKET_SIZE - 2] == PACKET_CR && packet_buffer[PACKET_SIZE - 1] == PACKET_LF) {
        Serial.println("Packet synchronized successfully (Non-Blocking FSM).");
        Serial.print("Raw Packet Data (FSM Success): ");
        for (int i = 0; i < PACKET_SIZE; i++) Serial.printf("%02X ", packet_buffer[i]);
        Serial.println();
        packet_ready = true;
        return true; 
      } else {
        Serial.printf("Sync Failed: Expected CR/LF, found 0x%02X, 0x%02X. Attempting shift resync.\n",
                      packet_buffer[PACKET_SIZE - 2], packet_buffer[PACKET_SIZE - 1]);
        for (int i = 1; i < PACKET_SIZE; i++) packet_buffer[i - 1] = packet_buffer[i];
        packet_index = PACKET_SIZE - 1; 
      }
    }
  }
  return false;
} 

void parseGammaData() {
  byte txvByte = packet_buffer[5];
  byte rssiRawByte = packet_buffer[7];
  current_data.batt_voltage = 1.8 + ((float)txvByte * 0.05);
  current_data.batt_ok = (current_data.batt_voltage >= BATT_LOW_THRESHOLD_V);
  current_data.rssi_dbm = -((float)rssiRawByte / 2.0);
  current_data.data_valid = true;
}  

void getTimestamp() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    strncpy(current_data.timestamp, "NTP Sync Failed", TIMESTAMP_SIZE);
    current_data.timestamp[TIMESTAMP_SIZE - 1] = '\0';
    return;
  }
  strftime(current_data.timestamp, TIMESTAMP_SIZE, "%H:%M:%S", &timeinfo);
}  

// --- LOGGING ---
void checkAndRotateLog() {
  if (!LittleFS.exists(LOG_FILE)) return; 
  File logFile = LittleFS.open(LOG_FILE, "r");
  if (!logFile) return; 
  size_t currentSize = logFile.size();
  logFile.close();
  if (currentSize > (MAX_LOG_SIZE_KB * 1024)) {
    Serial.printf("LOG ROTATION: File size %lu bytes exceeds %d KB limit.\n", currentSize, MAX_LOG_SIZE_KB);
    if (LittleFS.exists(LOG_OLD_FILE)) {
        LittleFS.remove(LOG_OLD_FILE);
        Serial.printf("LOG ROTATION: Deleted old file: %s\n", LOG_OLD_FILE);
    }
    if (LittleFS.rename(LOG_FILE, LOG_OLD_FILE)) {
      Serial.printf("LOG ROTATION: Renamed %s to %s.\n", LOG_FILE, LOG_OLD_FILE);
      logToLittleFS("INFO: LOG ROTATION successful. New log started.");
    }
  }
}

void logToLittleFS(const char* eventMessage) {
  checkAndRotateLog(); 
  if (!LittleFS.begin()) {
    Serial.println("FATAL: LittleFS not mounted. Cannot log event.");
    return;
  }
  File logFile = LittleFS.open(LOG_FILE, "a");
  if (!logFile) {
    Serial.println("Failed to open log file for appending.");
    return;
  }
  char timestamp_buffer[TIMESTAMP_SIZE + 32];
  if (time(nullptr) > 100000) {
    getTimestamp(); 
    strncpy(timestamp_buffer, (const char*)current_data.timestamp, sizeof(timestamp_buffer)); // CORE 3.x FIX
  } else {
    snprintf(timestamp_buffer, sizeof(timestamp_buffer), "ms:%lu", millis());
  }
  char logLine[LOG_MESSAGE_SIZE + TIMESTAMP_SIZE + 10];
  snprintf(logLine, sizeof(logLine), "[%s] %s\n", timestamp_buffer, eventMessage);
  logFile.print(logLine);
  logFile.close();
  Serial.printf("FS LOGGED: %s", logLine);
}

// --- HTTP SERVER ---
void sendFileToClient(const char* path) {
  File file = LittleFS.open(path, "r");
  if (!file) { server.send(404, "text/plain", "File not found."); return; }
  server.streamFile(file, "text/plain");
  file.close();
}

void handleRoot() {
  String html = "<html><head><title>Gate Alert Logs</title>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1.0'></head><body>";
  html += "<h1>Gate Alert System Diagnostic</h1>";
  html += "<p>Current Time: ";
  if (time(nullptr) > 100000) {
    getTimestamp();
    html += (const char*)current_data.timestamp; // CORE 3.x FIX
  } else {
    html += "NTP Sync Pending (Millis: " + String(millis()) + "ms)";
  }
  html += "</p><h2>Log Files</h2><ul>";
  if (LittleFS.exists(LOG_FILE)) {
    File log = LittleFS.open(LOG_FILE, "r");
    html += "<li>Current Log (<a href='/log.txt'>/log.txt</a>): " + String(log.size() / 1024.0, 2) + " KB</li>";
    log.close();
  }
  html += "</ul><h2>Actions</h2><p><a href='/clear'>[Click here to DELETE and START a NEW LOG]</a></p>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleLogClear() {
  Serial.println("Received request to clear logs.");
  logToLittleFS("INFO: LOG CLEAR REQUEST RECEIVED via HTTP.");
  if (LittleFS.exists(LOG_FILE)) LittleFS.remove(LOG_FILE);
  if (LittleFS.exists(LOG_OLD_FILE)) LittleFS.remove(LOG_OLD_FILE);
  logToLittleFS("INFO: ALL LOG FILES CLEARED."); 
  server.sendHeader("Location", "/", true);
  server.send(302, "text/plain", "Cleared.");
}

void initWebServer() {
  server.on("/", handleRoot);
  server.on("/log.txt", [](){ sendFileToClient(LOG_FILE); }); 
  server.on("/clear", handleLogClear);
  server.begin();
  Serial.print("HTTP Server started on IP: ");
  Serial.println(WiFi.localIP());
  logToLittleFS("INFO: Web server successfully started.");
}

// --- MQTT ---
void reconnectMQTT() {
  if (WiFi.status() != WL_CONNECTED) return;
  Serial.print("Attempting MQTT connection (Single attempt)...");
  if (mqttClient.connect(MQTT_CLIENT_ID, MQTT_USER, MQTT_PASS)) {
    Serial.println("connected");
  } else {
    Serial.print("failed, rc=");
    Serial.print(mqttClient.state());
    Serial.println(" (Failed attempt)");
  }
}  

void publishMQTTSimpleValue(const char* topicSuffix, float value, int precision, const char* unit) {
  if (!mqttClient.connected()) return;
  char fullTopic[64], floatPayload[10], textPayload[64]; 
  snprintf(fullTopic, sizeof(fullTopic), "home/blue_gate/%s", topicSuffix);
  dtostrf(value, 0, precision, floatPayload);
  snprintf(textPayload, sizeof(textPayload), "%s: %s %s", topicSuffix, floatPayload, unit);
  Serial.printf("Publishing to %s: %s\n", fullTopic, textPayload);
  mqttClient.publish(fullTopic, textPayload, false);
}  

void publishMQTTEvent() {
  if (!mqttClient.connected()) return;
  StaticJsonDocument<256> doc;
  doc["timestamp"] = current_data.timestamp;
  doc["gate_status"] = current_data.status;
  doc["data_valid"] = current_data.data_valid;
  if (current_data.data_valid) doc["battery_ok"] = current_data.batt_ok;
  else doc["error"] = "Serial data read failed";
  char jsonBuffer[256];
  serializeJson(doc, jsonBuffer);
  Serial.print("Publishing JSON to MQTT: ");
  Serial.println(jsonBuffer);
  mqttClient.publish(MQTT_TOPIC_STATUS, jsonBuffer, true);
  if (current_data.data_valid) {
    publishMQTTSimpleValue("RSSI_dBm", current_data.rssi_dbm, 1, "dBm");
    publishMQTTSimpleValue("battery_V", current_data.batt_voltage, 2, "V");
  }
}  

// RESTORED: Full Gold Narrative for Pushover
void sendPushover() {
  Serial.println("Attempting Pushover notification...");
  const char* sound_to_use = "";
  if (strcmp(current_data.status, "OPEN") == 0) sound_to_use = PUSHOVER_SOUND_OPEN; 
  else if (strcmp(current_data.status, "CLOSED") == 0) sound_to_use = PUSHOVER_SOUND_CLOSED;
  
  secureClient.setCACert(PUSHOVER_ROOT_CA);
  HTTPClient http;
  char url[URL_BUF_SIZE];
  snprintf(url, sizeof(url), "https://%s/1/messages.json", PUSHOVER_HOST);
  http.begin(secureClient, url); 
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");
  http.setTimeout(4000); 

  char messageContent[MESSAGE_BUF_SIZE];
  const char* statusPrefix = (strcmp(current_data.status, "OPEN") == 0) ? "OPEN @ " : "CLOSED @ ";
  snprintf(messageContent, sizeof(messageContent), "%s%s\n%.1f dBm %s (%.2f V)",
           statusPrefix, current_data.timestamp, current_data.rssi_dbm, 
           current_data.batt_ok ? "OK" : "LOW", current_data.batt_voltage);

  char encodedMessage[POSTDATA_BUF_SIZE];
  urlEncode(messageContent, encodedMessage, sizeof(encodedMessage));

  char postData[POSTDATA_BUF_SIZE];
  int len = 0;
  len += snprintf(postData + len, sizeof(postData) - len, "token=%s&user=%s&device=%s&message=%s", 
                  PUSHOVER_TOKEN, PUSHOVER_USER, PUSHOVER_DEVICE, encodedMessage);
  
  if (strlen(sound_to_use) > 0) {
      Serial.printf("  -> Sending sound: %s\n", sound_to_use);
      len += snprintf(postData + len, sizeof(postData) - len, "&sound=%s", sound_to_use);
  }

  Serial.printf("Pushover Post Data Length: %d\n", len);

  int httpResponseCode = http.POST(postData);
  char log_buffer[LOG_MESSAGE_SIZE];

  if (httpResponseCode == 200) {  
    Serial.printf("Pushover success! Response Code: %d\n", httpResponseCode);
    snprintf(log_buffer, sizeof(log_buffer), "PO: SUCCESS (%s) Response: 200", current_data.status);
    logToLittleFS(log_buffer); 
    Serial.println("--- INITIATING FLASH 2 (Red PO CONFIRM) ---");
    initBlink(LED_DRIVER_B, LED_DRIVER_A);
  } else if (httpResponseCode > 0) {
    Serial.printf("Pushover accepted, but response %d. NO RED FLASH.\n", httpResponseCode);
    snprintf(log_buffer, sizeof(log_buffer), "PO: ACCEPTED (%s) Response: %d", current_data.status, httpResponseCode);
    logToLittleFS(log_buffer);
  } else {
    Serial.printf("Pushover failed. Error: %s (%d). NO RED FLASH.\n", http.errorToString(httpResponseCode).c_str(), httpResponseCode);
    snprintf(log_buffer, sizeof(log_buffer), "PO: FAILED (%s) Error: %d", current_data.status, httpResponseCode);
    logToLittleFS(log_buffer);
  }
  http.end();
}

// --- LED BLINK ---
void initBlink(int sourcePin, int sinkPin) {
  blink_source_pin = sourcePin; blink_sink_pin = sinkPin;
  blink_stop_time_ms = millis() + FLASH_DURATION_MS;
  digitalWrite(blink_sink_pin, LOW); digitalWrite(blink_source_pin, HIGH);
}

void blinkHandler() {
  if (blink_source_pin != -1 && millis() >= blink_stop_time_ms) {
    digitalWrite(blink_source_pin, LOW); digitalWrite(blink_sink_pin, LOW);
    blink_source_pin = -1; blink_sink_pin = -1;
    Serial.println("LED blink finished (non-blocking).");
  }
} 

// --- NETWORK MANAGEMENT (MODIFIED: Grace Period) ---
void checkAndReconnectNetwork() {
  unsigned long currentMillis = millis();
  bool currently_connected = (WiFi.status() == WL_CONNECTED && mqttClient.connected());

  if (currently_connected) {
    last_wifi_ok_ms = currentMillis; 
    is_online_mode = true;
    reconnect_fail_count = 0;
  } else {
    if (currentMillis - last_wifi_ok_ms > WIFI_GRACE_PERIOD_MS) {
      if (is_online_mode) {
        Serial.println("WARNING: Lost network connection. Falling back to LOCAL MODE.");
        logToLittleFS("NET: WARNING - LOST CONNECTION (Falling to LOCAL).");
        is_online_mode = false;
        server.stop();
      }
    }
    
    if (currentMillis - last_reconnect_attempt_ms >= RECONNECT_INTERVAL_MS) {
      Serial.println("\n--- Non-Blocking Reconnection Attempt Triggered ---");
      last_reconnect_attempt_ms = currentMillis; 
      if (WiFi.status() != WL_CONNECTED) {
          Serial.print("Attempting Wi-Fi reconnect...");
          WiFi.reconnect();
      }
      if (WiFi.status() == WL_CONNECTED && !mqttClient.connected()) reconnectMQTT();
      
      if (WiFi.status() == WL_CONNECTED && mqttClient.connected()) {
        if (!is_online_mode) {
           Serial.println("Successfully reconnected. ONLINE MODE restored.");
           logToLittleFS("NET: ONLINE MODE RESTORED.");
           initWebServer();
        }
      } else {
        reconnect_fail_count++;
        Serial.printf("Failure count: %d/%d\n", reconnect_fail_count, MAX_RECONNECT_FAILURES);
        if (reconnect_fail_count >= MAX_RECONNECT_FAILURES) ESP.restart();
      }
    }
  }
} 

void setup() {
  Serial.begin(115200);
  esp_log_level_set("*", ESP_LOG_ERROR);
  Serial.println("\n--- Starting Dual-Input Gate Alert System ---");

  if (!LittleFS.begin(true)) Serial.println("FATAL: LITTLEFS MOUNT FAILED!");
  else logToLittleFS("INFO: LittleFS mounted successfully.");

  // 1. NTP Initialization with Multiple Sources (Improved Resilience)
  configTime(0, 0, "192.168.1.1", "ntp1.npl.co.uk", "pool.ntp.org");
  
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(SENSOR_PIN, INPUT_PULLUP);
  pinMode(LED_DRIVER_A, OUTPUT);
  pinMode(LED_DRIVER_B, OUTPUT);
  
  Serial2.begin(BAUD_RATE, SERIAL_8N1, SERIAL_RX_PIN, SERIAL_TX_PIN);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD); 
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  
  // BOOT SYNC: Set initial state immediately
  int startup_sensor = digitalRead(SENSOR_PIN);
  strncpy(current_data.status, (startup_sensor == LOW) ? "OPEN" : "CLOSED", STATUS_SIZE);
  char boot_msg[64];
  snprintf(boot_msg, sizeof(boot_msg), "BOOT SYNC: Gate is %s", current_data.status);
  logToLittleFS(boot_msg);

  attachInterrupt(digitalPinToInterrupt(BUTTON_PIN), handleGateInterrupt, CHANGE);
  attachInterrupt(digitalPinToInterrupt(SENSOR_PIN), handleGateInterrupt, CHANGE);
  
  isr_button_state = digitalRead(BUTTON_PIN);
  isr_sensor_state = digitalRead(SENSOR_PIN);
}  

void loop() {
  blinkHandler();
  checkAndReconnectNetwork();
  if (is_online_mode) {
    mqttClient.loop();
    server.handleClient();
  }

  // FORCE NTP SYNC (Background Retry if not synced)
  if (time(nullptr) < 100000 && (millis() - last_ntp_sync_attempt_ms > NTP_RETRY_INTERVAL_MS)) {
    last_ntp_sync_attempt_ms = millis();
    configTime(0, 0, "192.168.1.1", "ntp1.npl.co.uk", "pool.ntp.org");
  }

  if (serialReadHandler()) {
    Serial.println("--- Serial Data Received (Main Loop - Packet Ready) ---");
    parseGammaData(); 
    Serial.println("--- INITIATING FLASH 1 (Green RX) ---");
    initBlink(LED_DRIVER_A, LED_DRIVER_B);
    packet_ready = false; packet_index = 0;
  }

  if (queue_head != queue_tail) {
    Event next_event;
    memcpy(&next_event, (const void*)&event_queue[queue_tail], sizeof(Event));
    queue_tail = (queue_tail + 1) % MAX_QUEUE_SIZE;

    Serial.println("--- Gate Event Fired (Main Loop - From Queue) ---");
    char event_log[64];
    snprintf(event_log, sizeof(event_log), "GATE EVENT: %s detected by %s.", next_event.status, next_event.source);
    logToLittleFS(event_log); 

    if (WiFi.status() == WL_CONNECTED) getTimestamp(); 
    else strncpy(current_data.timestamp, "LOCAL", TIMESTAMP_SIZE);

    strncpy(current_data.status, next_event.status, STATUS_SIZE);
    Serial.printf("Trigger Source: %s - Detected State: %s\n", next_event.source, current_data.status);

    if (WiFi.status() == WL_CONNECTED && time(nullptr) > 100000) {
        Serial.println("WiFi connected. Time synchronized. Attempting SECURE notifications...");
        sendPushover(); 
        if (is_online_mode) publishMQTTEvent();
    } else {
        Serial.println("WARNING: Sync failed or offline. Skipping notifications.");
    }
  }
  delay(10);
}
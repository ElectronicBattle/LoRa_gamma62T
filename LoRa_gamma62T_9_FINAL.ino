// DFRobot FireBeetle 2 ESP32-E (DFR0654) - IoT Gate Alert System

//WDT & System	Watchdog Timer (WDT) Implementation	Completed. 
//Added esp_task_wdt_init() and periodic esp_task_wdt_reset() to prevent code hangs.

//ISR & Queue	ISR Safety & Event Queueing	Completed. 
//Critical interrupt logic is short, uses volatile C-strings, and offloads processing to the main loop queue.

//Phase 2, Rank 3	Non-Blocking LED Blink	Completed. 
//Replaced any blocking delay() calls with the initBlink() and blinkHandler() FSM.

//Phase 2, Rank 4	Replace Arduino String Usage	Completed. 
//All dynamic strings and buffers use C-style char[] arrays and safe functions like snprintf and urlEncode.

//Phase 3, Rank 5	Non-Blocking Stateful Serial FSM	Completed. 
//The unreliable blocking readGammaData() is replaced by the robust serialReadHandler() FSM in the main loop.

//Phase 3, Rank 6	Exponential Backoff with Jitter	Not Implemented (Replaced):
//The final sketch uses the simpler fixed interval (5s) reconnection logic (RECONNECT_INTERVAL_MS). 
//This is stable and was preferred over the more complex backoff logic we had started.

//MQTT/Network	Network Failure Counter Reset	Completed. 
//The reconnect_fail_count is correctly reset when the device is stable and online, preventing false alarms.

//Diagnostic	Brownout/WDT Reset Diagnostics	Completed. 
//The setup() function now checks and logs the reset reason, which is vital for diagnosing power or code issues.

//Final Stable Version: Non-Blocking Serial FSM Implemented.



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

// --- FIX: ADD FUNCTION PROTOTYPES FOR LINKER ERROR ---
void setup();
void loop();
void reconnectMQTT();
void checkAndReconnectNetwork();
void initBlink(int sourcePin, int sinkPin); 
void blinkHandler();                         
void urlEncode(const char* input, char* output, size_t outputSize);
bool serialReadHandler(); // NEW NON-BLOCKING FSM
void sendPushover();     
// ---------------------------------------------------

// ---------------------------------------------------------------------
// --- HARDWARE & SERIAL CONFIGURATION ---
// ---------------------------------------------------------------------

// --- WDT CONFIGURATION ---
#define WDT_TIMEOUT_SEC 5  
// -------------------------

// --- LOW BATTERY THRESHOLD ---
#define BATT_LOW_THRESHOLD_V 2.00

// --- INPUT PINS ---
#define BUTTON_PIN 27 
#define SENSOR_PIN 4   

// --- BI-COLOUR LED PINS (NEW SOURCE/SINK LOGIC) ---
#define LED_DRIVER_A            16 
#define LED_DRIVER_B            14  

// --- LED TIMING (Global) ---
const unsigned long FLASH_DURATION_MS = 100;  

// --- SERIAL CONFIGURATION ---
#define SERIAL_RX_PIN 25  
#define SERIAL_TX_PIN 17  
#define BAUD_RATE 19200

// Data Packet Structure (Gamma62T protocol)
#define PACKET_SIZE 10
byte packet_buffer[PACKET_SIZE] = { 0 };

// --- DEFINITIONS REQUIRED FOR SERIAL SYNCHRONIZATION ---
#define PACKET_CR 0x0D  
#define PACKET_LF 0x0A  

// --- NEW DEFINITIONS FOR C-STRING BUFFERS ---
#define TIMESTAMP_SIZE 16   
#define STATUS_SIZE 10      
#define MESSAGE_BUF_SIZE 150 
#define POSTDATA_BUF_SIZE 512 
#define URL_BUF_SIZE 64     
// ----------------------------------------------------

// ----------------------------------------------------
// --- GLOBAL OBJECTS & STATE MANAGEMENT ---
// ----------------------------------------------------

WiFiClient espClient;
WiFiClientSecure secureClient;
PubSubClient mqttClient(espClient);

// --- GLOBAL VARIABLES FOR NON-BLOCKING RECONNECT ---
const unsigned long RECONNECT_INTERVAL_MS = 5000; 
unsigned long last_reconnect_attempt_ms = 0;
bool is_online_mode = false; 

// --- NEW AUTO-REBOOT COUNTER ---
const int MAX_RECONNECT_FAILURES = 10;
int reconnect_fail_count = 0; 

// --- GLOBAL VARIABLES FOR NON-BLOCKING BLINK ---
volatile unsigned long blink_stop_time_ms = 0; 
volatile int blink_source_pin = -1;            
volatile int blink_sink_pin = -1;              
// -------------------------------------------------------------------

// --- NEW GLOBAL VARIABLES FOR SERIAL FSM ---
volatile bool packet_ready = false;  
volatile size_t packet_index = 0;    
const unsigned long SERIAL_TIMEOUT_MS = 500; 
unsigned long packet_start_time = 0; 
// -------------------------------------------

// Structure to store a single event
struct Event
{
  char status[STATUS_SIZE];
  char source[STATUS_SIZE];
};

// Define the queue size
#define MAX_QUEUE_SIZE 5
volatile Event event_queue[MAX_QUEUE_SIZE];
volatile int queue_head = 0;
volatile int queue_tail = 0;

// Volatile variables to hold the last stable state read by the ISR
volatile int isr_button_state = HIGH;
volatile int isr_sensor_state = HIGH;

// Debouncing and timing
volatile unsigned long last_interrupt_time = 0;
const unsigned long DEBOUNCE_DELAY_MS = 25;

struct GateData
{
  char timestamp[TIMESTAMP_SIZE]; 
  char status[STATUS_SIZE];       
  float rssi_dbm = 0.0;
  float batt_voltage = 0.0;
  bool batt_ok = false;
  bool data_valid = false;
} current_data;


// ----------------------------------------------------
// --- INTERRUPT HANDLER (Unmodified) ---
// ----------------------------------------------------

void IRAM_ATTR handleGateInterrupt()
{
  unsigned long interrupt_time = millis();

  int current_btn = digitalRead(BUTTON_PIN);
  int current_sensor = digitalRead(SENSOR_PIN);

  if (interrupt_time - last_interrupt_time > DEBOUNCE_DELAY_MS)
  {
    bool btn_changed = (current_btn != isr_button_state);
    bool sensor_changed = (current_sensor != isr_sensor_state);

    if (btn_changed || sensor_changed)
    {
      if (((queue_head + 1) % MAX_QUEUE_SIZE) != queue_tail)
      {
        const char* new_status;
        const char* new_source;

        if (sensor_changed)
        {
          new_status = (current_sensor == LOW) ? "OPEN" : "CLOSED";
          new_source = "SENSOR";
        }
        else if (btn_changed)
        {
          new_status = (current_btn == LOW) ? "CLOSED" : "OPEN";
          new_source = "BUTTON";
        }

        volatile Event* current_event = &event_queue[queue_head];
        const size_t STATUS_SIZE_E = sizeof(current_event->status);
        const size_t SOURCE_SIZE_E = sizeof(current_event->source);

        strncpy((char*)current_event->status, new_status, STATUS_SIZE_E - 1);
        current_event->status[STATUS_SIZE_E - 1] = '\0'; 

        strncpy((char*)current_event->source, new_source, SOURCE_SIZE_E - 1);
        current_event->source[SOURCE_SIZE_E - 1] = '\0';

        queue_head = (queue_head + 1) % MAX_QUEUE_SIZE;

        last_interrupt_time = interrupt_time;
        isr_button_state = current_btn;
        isr_sensor_state = current_sensor;
      }
    }
  }
} 


// ----------------------------------------------------
// --- DATA PARSING & TIME & UTILITY FUNCTIONS ---
// ----------------------------------------------------

void urlEncode(const char* input, char* output, size_t outputSize)
{
  size_t input_len = strlen(input);
  size_t encoded_index = 0;

  for (size_t i = 0; i < input_len; i++) 
  {
    char c = input[i];
    
    if (encoded_index >= outputSize - 4) {
      break; 
    }
    
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      output[encoded_index++] = c;
    }
    else if (c == ' ')
    {
      output[encoded_index++] = '+';
    }
    else
    {
      output[encoded_index++] = '%';
      
      char code1 = (c >> 4) & 0xF;
      char code0 = c & 0xF;
      
      output[encoded_index++] = (char)((code1 < 10) ? (code1 + '0') : (code1 - 10 + 'A'));
      output[encoded_index++] = (char)((code0 < 10) ? (code0 + '0') : (code0 - 10 + 'A'));
    }
  }
  output[encoded_index] = '\0'; 
}


// --- NEW NON-BLOCKING SERIAL HANDLER (FSM) ---
bool serialReadHandler()
{
  if (packet_ready) {
    return true; 
  }
  
  // 1. Timeout Check
  if (packet_index > 0 && millis() - packet_start_time > SERIAL_TIMEOUT_MS)
  {
    Serial.printf("Serial Timeout: Packet incomplete after %lu ms. Resetting parser.\n", SERIAL_TIMEOUT_MS);
    while(Serial2.available()) Serial2.read(); 
    packet_index = 0; 
    return false;
  }

  // 2. Read Incoming Bytes
  while (Serial2.available() > 0)
  {
    byte incoming_byte = Serial2.read();
    
    if (packet_index == 0)
    {
      packet_start_time = millis(); 
    }
    
    packet_buffer[packet_index++] = incoming_byte;
    
    // 3. Full Packet Check (10 bytes received)
    if (packet_index == PACKET_SIZE)
    {
      // 4. Synchronization Check (CR/LF)
      if (packet_buffer[PACKET_SIZE - 2] == PACKET_CR && packet_buffer[PACKET_SIZE - 1] == PACKET_LF)
      {
        Serial.println("Packet synchronized successfully (Non-Blocking FSM).");
        
        Serial.print("Raw Packet Data (FSM Success): ");
        for (int i = 0; i < PACKET_SIZE; i++) {
          Serial.printf("%02X ", packet_buffer[i]);
        }
        Serial.println();
        
        packet_ready = true;
        return true; 
      }
      else
      {
        // 5. Synchronization Failure: Shift resync
        Serial.printf("Sync Failed: Expected CR/LF, found 0x%02X, 0x%02X. Attempting shift resync.\n",
                      packet_buffer[PACKET_SIZE - 2], packet_buffer[PACKET_SIZE - 1]);
        
        for (int i = 1; i < PACKET_SIZE; i++)
        {
          packet_buffer[i - 1] = packet_buffer[i];
        }
        packet_index = PACKET_SIZE - 1; 
      }
    }
  }
  
  return false;
} 


void parseGammaData() 
{
  byte txvByte = packet_buffer[5];
  byte rssiRawByte = packet_buffer[7];

  current_data.batt_voltage = 1.8 + ((float)txvByte * 0.05);
  current_data.batt_ok = (current_data.batt_voltage >= BATT_LOW_THRESHOLD_V);
  current_data.rssi_dbm = -((float)rssiRawByte / 2.0);
  current_data.data_valid = true;
}  

void getTimestamp() 
{
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo))
  {
    strncpy(current_data.timestamp, "NTP Sync Failed", TIMESTAMP_SIZE);
    current_data.timestamp[TIMESTAMP_SIZE - 1] = '\0';
    return;
  }
  strftime(current_data.timestamp, TIMESTAMP_SIZE, "%H:%M:%S", &timeinfo);
}  

// ----------------------------------------------------
// --- MQTT FUNCTIONS (Unmodified) ---
// ----------------------------------------------------

void reconnectMQTT()
{
  if (WiFi.status() != WL_CONNECTED) return;
  Serial.print("Attempting MQTT connection (Single attempt)...");
  if (mqttClient.connect(MQTT_CLIENT_ID, MQTT_USER, MQTT_PASS))
  {
    Serial.println("connected");
  }
  else
  {
    Serial.print("failed, rc=");
    Serial.print(mqttClient.state());
    Serial.println(" (Failed attempt)");
  }
}  

void publishMQTTSimpleValue(const char* topicSuffix, float value, int precision, const char* unit)
{
  if (!mqttClient.connected()) return;

  char fullTopic[64];
  char floatPayload[10];
  char textPayload[64]; 
  
  snprintf(fullTopic, sizeof(fullTopic), "home/blue_gate/%s", topicSuffix);
  dtostrf(value, 0, precision, floatPayload);
  snprintf(textPayload, sizeof(textPayload), "%s: %s %s", topicSuffix, floatPayload, unit);
  Serial.printf("Publishing to %s: %s\n", fullTopic, textPayload);
  mqttClient.publish(fullTopic, textPayload, false);
}  

void publishMQTTEvent()
{
  if (!mqttClient.connected()) return;

  StaticJsonDocument<256> doc;

  doc["timestamp"] = current_data.timestamp;
  doc["gate_status"] = current_data.status;
  doc["data_valid"] = current_data.data_valid;

  if (current_data.data_valid)
  {
    doc["battery_ok"] = current_data.batt_ok;
  }
  else
  {
    doc["error"] = "Serial data read failed";
  }

  char jsonBuffer[256];
  serializeJson(doc, jsonBuffer);

  Serial.print("Publishing JSON to MQTT topic ");
  Serial.print(MQTT_TOPIC_STATUS);
  Serial.print(": ");
  Serial.println(jsonBuffer);

  mqttClient.publish(MQTT_TOPIC_STATUS, jsonBuffer, true);

  if (current_data.data_valid)
  {
    publishMQTTSimpleValue("RSSI_dBm", current_data.rssi_dbm, 1, "dBm");
    publishMQTTSimpleValue("battery_V", current_data.batt_voltage, 2, "V");
  }
}  

// ----------------------------------------------------
// --- PUSHOVER FUNCTIONS (Unmodified) ---
// ----------------------------------------------------

void sendPushover()
{
  Serial.println("Attempting Pushover notification...");
  secureClient.setInsecure();
  HTTPClient http;

  char url[URL_BUF_SIZE];
  snprintf(url, sizeof(url), "https://%s/1/messages.json", PUSHOVER_HOST);
  http.begin(secureClient, url);
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");
  http.setTimeout(4000); 

  char messageContent[MESSAGE_BUF_SIZE];
  const char* statusPrefix = (strcmp(current_data.status, "OPEN") == 0) ? "Blue Gate OPEN @ " : "Blue Gate CLOSED @ ";

  snprintf(messageContent, sizeof(messageContent), 
           "%s%s %.1f dBm %s (%.2f V)",
           statusPrefix,
           current_data.timestamp,
           current_data.rssi_dbm,
           current_data.batt_ok ? "OK" : "LOW",
           current_data.batt_voltage);

  char encodedMessage[POSTDATA_BUF_SIZE];
  urlEncode(messageContent, encodedMessage, sizeof(encodedMessage));

  char postData[POSTDATA_BUF_SIZE];
  int len = 0;
  
  len += snprintf(postData + len, sizeof(postData) - len, "token=%s", PUSHOVER_TOKEN);
  len += snprintf(postData + len, sizeof(postData) - len, "&user=%s", PUSHOVER_USER);
  len += snprintf(postData + len, sizeof(postData) - len, "&device=%s", PUSHOVER_DEVICE);
  len += snprintf(postData + len, sizeof(postData) - len, "&message=%s", encodedMessage);

  Serial.printf("Pushover Post Data Length: %d\n", len);

  int httpResponseCode = http.POST(postData);

  if (httpResponseCode == 200)
  {  
    Serial.printf("Pushover success! Response Code: %d\n", httpResponseCode);
    Serial.println("--- INITIATING FLASH 2 (Red PO CONFIRM) ---");
    initBlink(LED_DRIVER_B, LED_DRIVER_A);

  }
  else if (httpResponseCode > 0)
  {
    Serial.printf("Pushover accepted, but response %d. NO RED FLASH.\n", httpResponseCode);
  }
  else
  {
    Serial.printf("Pushover failed. Error: %s (%d). NO RED FLASH.\n", http.errorToString(httpResponseCode).c_str(), httpResponseCode);
  }

  http.end();
}  

// ----------------------------------------------------
// --- NON-BLOCKING LED BLINK FUNCTIONS (Unmodified) ---
// ----------------------------------------------------

void initBlink(int sourcePin, int sinkPin)
{
  blink_source_pin = sourcePin;
  blink_sink_pin = sinkPin;

  blink_stop_time_ms = millis() + FLASH_DURATION_MS;

  digitalWrite(blink_sink_pin, LOW);
  digitalWrite(blink_source_pin, HIGH);
}

void blinkHandler()
{
  if (blink_source_pin != -1) 
  {
    if (millis() >= blink_stop_time_ms)
    {
      digitalWrite(blink_source_pin, LOW);
      digitalWrite(blink_sink_pin, LOW);
      
      blink_source_pin = -1;
      blink_sink_pin = -1;

      Serial.println("LED blink finished (non-blocking).");
    }
  }
} 


// ----------------------------------------------------
// --- NON-BLOCKING NETWORK MANAGEMENT (MODIFIED) ---
// ----------------------------------------------------

void checkAndReconnectNetwork()
{
  unsigned long currentMillis = millis();

  if (!is_online_mode || !mqttClient.connected()) 
  {
    if (currentMillis - last_reconnect_attempt_ms >= RECONNECT_INTERVAL_MS)
    {
      Serial.println("\n--- Non-Blocking Reconnection Attempt Triggered ---");
      last_reconnect_attempt_ms = currentMillis; 

      if (WiFi.status() != WL_CONNECTED)
      {
        Serial.print("Attempting Wi-Fi reconnect...");
        WiFi.reconnect();
      }
      
      if (WiFi.status() == WL_CONNECTED && !mqttClient.connected())
      {
        reconnectMQTT(); 
      }
      
      bool was_online_mode = is_online_mode;
      is_online_mode = (WiFi.status() == WL_CONNECTED && mqttClient.connected());
      
      if (is_online_mode && !was_online_mode) 
      {
         Serial.println("Successfully reconnected to network and MQTT. ONLINE MODE restored.");
         configTime(0, 0, "pool.ntp.org");
         reconnect_fail_count = 0;
      } 
      else if (was_online_mode && !is_online_mode) 
      {
         Serial.println("WARNING: Lost network connection. Falling back to LOCAL MODE.");
         reconnect_fail_count++;
      } 
      else if (!is_online_mode)
      {
         reconnect_fail_count++;
         Serial.printf("Reconnection attempt done. Current mode: LOCAL. Failure count: %d/%d\n", 
                        reconnect_fail_count, MAX_RECONNECT_FAILURES);

         if (reconnect_fail_count >= MAX_RECONNECT_FAILURES)
         {
           Serial.println("\n!!! MAX RECONNECT FAILURES REACHED !!! Initiating ESP32 Hard Reset.");
           ESP.restart(); 
           delay(500); 
         }
      }
    }
  }
  else
  {
      // *** FIX: Reset failure count if currently online and stable ***
      if (WiFi.status() == WL_CONNECTED && mqttClient.connected()) {
          reconnect_fail_count = 0;
      } else {
          is_online_mode = false;
          reconnect_fail_count++;
      }
  }
} 


// ----------------------------------------------------
// --- SETUP and LOOP (MODIFIED for FSM integration) ---
// ----------------------------------------------------

void setup()
{
  randomSeed(analogRead(A0)); 
  Serial.begin(115200);

  Serial.println("\n--- Starting Dual-Input Gate Alert System ---");

  // --- Reset Reason Check for Diagnostics (NEW) ---
  esp_reset_reason_t reason = esp_reset_reason();

  if (reason == ESP_RST_BROWNOUT) {
    Serial.println("!!! ⚠️ WARNING: System reset due to BROWNOUT (Power Supply Issue) !!!");
  } else if (reason == ESP_RST_WDT) {
    Serial.println("!!! ⚠️ WARNING: System reset due to WATCHDOG TIMER (Code Blocked) !!!");
  } else if (reason == ESP_RST_SW) {
    Serial.println("System reset was software-triggered (ESP.restart()).");
  } else {
    Serial.printf("System initialized after reset (Reason Code: %d).\n", reason);
  }
  // ------------------------------------------

  // --- WDT SETUP ---
  const esp_task_wdt_config_t wdt_config = {
    WDT_TIMEOUT_SEC,                     
    (1 << CONFIG_ARDUINO_RUNNING_CORE),  
    true                                 
  };
  esp_task_wdt_init(&wdt_config);
  esp_task_wdt_add(NULL);
  Serial.printf("Task Watchdog Timer enabled with %d second timeout.\n", WDT_TIMEOUT_SEC);
  // -----------------

  Serial2.begin(BAUD_RATE, SERIAL_8N1, SERIAL_RX_PIN, SERIAL_TX_PIN);

  // 1. GPIO Setup
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(SENSOR_PIN, INPUT_PULLUP);
  pinMode(LED_DRIVER_A, OUTPUT);
  pinMode(LED_DRIVER_B, OUTPUT);
  digitalWrite(LED_DRIVER_A, LOW);
  digitalWrite(LED_DRIVER_B, LOW);

  isr_button_state = digitalRead(BUTTON_PIN);
  isr_sensor_state = digitalRead(SENSOR_PIN);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD); 
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  
  is_online_mode = false;
  last_reconnect_attempt_ms = millis() - RECONNECT_INTERVAL_MS; 
  
  if (WiFi.status() == WL_CONNECTED && mqttClient.connected()) 
  {
      is_online_mode = true;
  }
  
  delay(1000);

  attachInterrupt(digitalPinToInterrupt(BUTTON_PIN), handleGateInterrupt, CHANGE);
  attachInterrupt(digitalPinToInterrupt(SENSOR_PIN), handleGateInterrupt, CHANGE);

  isr_button_state = digitalRead(BUTTON_PIN);
  isr_sensor_state = digitalRead(SENSOR_PIN);
}  

void loop()
{
  // --- 1. WDT, LED, Network, MQTT Handlers ---
  esp_task_wdt_reset();
  blinkHandler();
  checkAndReconnectNetwork();
  if (is_online_mode)
  {
    mqttClient.loop();
  }

  // --- 2. NON-BLOCKING SERIAL PACKET CONSUMPTION (FSM) ---
  if (serialReadHandler()) 
  {
    Serial.println("--- Serial Data Received (Main Loop - Packet Ready) ---");
    parseGammaData(); // Updates current_data struct
    
    // Green Flash confirms packet arrival and successful parsing
    Serial.println("--- INITIATING FLASH 1 (Green RX) ---");
    initBlink(LED_DRIVER_A, LED_DRIVER_B);
    
    packet_ready = false; // Consume and reset the FSM flag
    packet_index = 0;
  }
  
  
  // --- 3. EVENT QUEUE PROCESSING ---
  if (queue_head != queue_tail)
  {
    Event next_event;
    memcpy(&next_event, (const void*)&event_queue[queue_tail], sizeof(Event));
    queue_tail = (queue_tail + 1) % MAX_QUEUE_SIZE;

    Serial.println("--- Gate Event Fired (Main Loop - From Queue) ---");

    // Capture Timestamp, use the most recent data status
    if (WiFi.status() == WL_CONNECTED)
    {
      getTimestamp(); 
    }
    else
    {
      strncpy(current_data.timestamp, "LOCAL TIME UNKNOWN", TIMESTAMP_SIZE);
      current_data.timestamp[TIMESTAMP_SIZE - 1] = '\0';
    }

    strncpy(current_data.status, next_event.status, STATUS_SIZE);
    current_data.status[STATUS_SIZE - 1] = '\0'; 

    Serial.printf("Trigger Source: %s - Detected State: %s\n", next_event.source, current_data.status);

    // Check if the data was updated by serialReadHandler() this loop, otherwise use defaults
    if (!current_data.data_valid)
    {
      // If the event fired before the serial packet arrived, clear RSSI/Batt data.
      current_data.rssi_dbm = 0.0;
      current_data.batt_voltage = 0.0;
      current_data.batt_ok = false;
      Serial.println("WARNING: Event fired with no recent Gamma data (data_valid=false).");
    }


    if (WiFi.status() == WL_CONNECTED)
    {
      Serial.println("WiFi connected. Attempting notifications...");

      // Blocking call that triggers Red Flash on success
      sendPushover(); 

      if (is_online_mode) 
      {
        publishMQTTEvent();
      }
    }
    else
    {
      Serial.println("No WiFi connection. Notifications skipped (LOCAL MODE).");
    }

    Serial.println("--- Event Handled ---\n");
  }

  delay(10);
}
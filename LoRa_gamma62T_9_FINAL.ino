// DFRobot FireBeetle 2 ESP32-E (DFR0654) - IoT Gate Alert System
// Includes WDT stability, interrupt queueing, serial sync
// non-blocking network logic, and power-up stabilization fixes
// Green Flash is Sync (serial RX Confirm). Red Flash is ASYNC (Pushover 200 OK Confirm)
// 4 second HTTP Timeout in sendPushover() for WDT safety
// Added Non-Blocking Network Reconnection Logic
// Timestamp capture moved for closer alignment with event trigger
// ALL OK for "production" 22/11/25
// starting to add duck.ai recommended improvements beginning with
// Phase 1, Rank 2: ISR Safety (COMPLETED)
// Phase 2, Rank 3: Non-Blocking LED Blink (COMPLETED)
// Phase 2, Rank 4: Replace Arduino String Usage (NEW)
// 

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <string.h>  // For interrupt-safe strcpy/memcpy
#include <secrets.h> // stored at ~/Arduino/libraries/secrets/secrets.h
#include <ctype.h>   // For isalnum in C-style urlEncode

// --- WDT HEADER ---
#include "esp_task_wdt.h"
// ------------------

// --- FIX: ADD FUNCTION PROTOTYPES FOR LINKER ERROR ---
void setup();
void loop();
void reconnectMQTT();
void checkAndReconnectNetwork();
void initBlink(int sourcePin, int sinkPin); 
void blinkHandler();                         
void urlEncode(const char* input, char* output, size_t outputSize); // NEW C-STRING PROTOTYPE
// ---------------------------------------------------

// ---------------------------------------------------------------------
// --- HARDWARE & SERIAL CONFIGURATION ---
// ---------------------------------------------------------------------

// --- WDT CONFIGURATION ---
#define WDT_TIMEOUT_SEC 5  // Watchdog timeout in seconds
// -------------------------

// --- LOW BATTERY THRESHOLD ---
#define BATT_LOW_THRESHOLD_V 2.00

// --- INPUT PINS ---
#define BUTTON_PIN 27  // Built-in button (GPIO 27 / D4)
#define SENSOR_PIN 4   // EXTERNAL SENSOR PIN (Silkscreen 4)

// --- BI-COLOUR LED PINS (NEW SOURCE/SINK LOGIC) ---
#define LED_DRIVER_A            16  // GPIO 16: Pin for one LED leg (Driver A)
#define LED_DRIVER_B            14  // GPIO 14: Pin for the other LED leg (Driver B)

// --- LED TIMING (Global) ---
const unsigned long FLASH_DURATION_MS = 100;  // Duration for LED flash

// --- SERIAL CONFIGURATION ---
#define SERIAL_RX_PIN 25  // RX pin for Serial2
#define SERIAL_TX_PIN 17  // TX pin for Serial2 (not used for RX-only)
#define BAUD_RATE 19200

// Data Packet Structure (Gamma62T protocol)
#define PACKET_SIZE 10
byte packet_buffer[PACKET_SIZE] = { 0 };

// --- DEFINITIONS REQUIRED FOR SERIAL SYNCHRONIZATION ---
#define PACKET_CR 0x0D  // Carriage Return
#define PACKET_LF 0x0A  // Line Feed

// --- NEW DEFINITIONS FOR C-STRING BUFFERS ---
#define TIMESTAMP_SIZE 16   // e.g., "12:34:56" + null
#define STATUS_SIZE 10      // "OPEN" or "CLOSED" + null (Event struct is 10)
#define MESSAGE_BUF_SIZE 150 // Buffer for Pushover message content
#define POSTDATA_BUF_SIZE 512 // Buffer for Pushover final POST body
#define URL_BUF_SIZE 64     // Buffer for HTTPS URL
// ----------------------------------------------------

// ----------------------------------------------------
// --- GLOBAL OBJECTS & EVENT QUEUE ---
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

// --- NEW GLOBAL VARIABLES FOR NON-BLOCKING BLINK (STATE MACHINE) ---
volatile unsigned long blink_stop_time_ms = 0; 
volatile int blink_source_pin = -1;            
volatile int blink_sink_pin = -1;              
// -------------------------------------------------------------------

// Structure to store a single event (using char arrays for interrupt safety)
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

// --- REPLACED STRING MEMBERS WITH CHAR ARRAYS ---
struct GateData
{
  char timestamp[TIMESTAMP_SIZE]; // Max 16 chars
  char status[STATUS_SIZE];       // Max 10 chars
  float rssi_dbm = 0.0;
  float batt_voltage = 0.0;
  bool batt_ok = false;
  bool data_valid = false;
} current_data;
// ---------------------------------------------


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

        // --- Push Event onto Queue using strncpy for safety ---
        volatile Event* current_event = &event_queue[queue_head];
        const size_t STATUS_SIZE_E = sizeof(current_event->status);
        const size_t SOURCE_SIZE_E = sizeof(current_event->source);

        // Copy Status
        strncpy((char*)current_event->status, new_status, STATUS_SIZE_E - 1);
        current_event->status[STATUS_SIZE_E - 1] = '\0'; 

        // Copy Source
        strncpy((char*)current_event->source, new_source, SOURCE_SIZE_E - 1);
        current_event->source[SOURCE_SIZE_E - 1] = '\0';
        // -----------------------------------------------------------

        queue_head = (queue_head + 1) % MAX_QUEUE_SIZE;

        last_interrupt_time = interrupt_time;
        isr_button_state = current_btn;
        isr_sensor_state = current_sensor;
      }
    }
  }
} // <-- END of handleGateInterrupt()


// ----------------------------------------------------
// --- DATA PARSING & TIME & UTILITY FUNCTIONS ---
// ----------------------------------------------------

// --- REPLACED: C-string urlEncode function (writes to a buffer) ---
void urlEncode(const char* input, char* output, size_t outputSize)
{
  size_t input_len = strlen(input);
  size_t encoded_index = 0;

  for (size_t i = 0; i < input_len; i++) 
  {
    char c = input[i];
    
    // Check if the output buffer has enough space for the current character:
    // 1 byte for safe chars, 3 bytes for encoded chars, 1 byte for null terminator
    if (encoded_index >= outputSize - 4) {
      break; // Stop if output buffer is nearly full
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
      // URL encode using hex values: %XX
      output[encoded_index++] = '%';
      
      char code1 = (c >> 4) & 0xF;
      char code0 = c & 0xF;
      
      output[encoded_index++] = (char)((code1 < 10) ? (code1 + '0') : (code1 - 10 + 'A'));
      output[encoded_index++] = (char)((code0 < 10) ? (code0 + '0') : (code0 - 10 + 'A'));
    }
  }
  output[encoded_index] = '\0'; // Null-terminate the string
}


// Attempts to read the full 10-byte packet from Serial2 (Gamma62T) with CR/LF Synchronization (Unmodified)
bool readGammaData()
{
  unsigned long timeout = millis() + 500;

  // We will discard single bytes until we find the start of a packet,
  // which we assume is 10 bytes before the end markers.
  while (millis() < timeout)
  {

    // Step 1: Wait until at least one byte of the packet has been received.
    if (Serial2.available() < PACKET_SIZE)
    {
      continue;
    }

    // Step 2: Ensure we clear any excess data to find a clean start.
    // Discard old data until the buffer contains exactly PACKET_SIZE (10) bytes.
    while (Serial2.available() > PACKET_SIZE)
    {
      Serial2.read();
    }

    // At this point, Serial2.available() is likely 10 or slightly more.

    // Step 3: Read the next 10 bytes into the packet_buffer.
    if (Serial2.available() >= PACKET_SIZE)
    {

      for (int i = 0; i < PACKET_SIZE; i++)
      {
        packet_buffer[i] = Serial2.read();
      }

      // Step 4: Verify the end markers (CR and LF.
      if (packet_buffer[PACKET_SIZE - 2] == PACKET_CR && packet_buffer[PACKET_SIZE - 1] == PACKET_LF)
      {

        Serial.println("Packet synchronized successfully by reading 10-byte block with CR/LF markers.");

        // OPTIONAL: Print the raw hex data for debugging success
        Serial.print("Raw Packet Data: ");
        for (int i = 0; i < PACKET_SIZE; i++)
        {
          Serial.printf("%02X ", packet_buffer[i]);
        }
        Serial.println();

        return true;
      }
      else
      {
        // Synchronization failed. Log the unexpected bytes.
        Serial.printf("Sync Failed: Expected CR/LF, but found 0x%02X, 0x%02X. Waiting for re-sync...\n",
                      packet_buffer[PACKET_SIZE - 2], packet_buffer[PACKET_SIZE - 1]);
      }
    }
  }

  Serial.printf("Serial read failed: Timed out after %lu ms.\n", millis() - (timeout - 500));
  // Clear the buffer just in case
  while (Serial2.available())
  {
    Serial2.read();
  }
  return false;
}  // <-- END of readGammaData()

void parseGammaData() // Unmodified
{
  byte txvByte = packet_buffer[5];
  byte statByte = packet_buffer[6];
  byte rssiRawByte = packet_buffer[7];

  // 1. Calculate Voltage (1.8 + (TXV * 0.05))
  current_data.batt_voltage = 1.8 + ((float)txvByte * 0.05);

  // 2. Set Battery Status based on actual voltage
  current_data.batt_ok = (current_data.batt_voltage >= BATT_LOW_THRESHOLD_V);

  // 3. Calculate RSSI
  current_data.rssi_dbm = -((float)rssiRawByte / 2.0);

  current_data.data_valid = true;
}  // <-- END of parseGammaData()

// --- MODIFIED: Writes timestamp to current_data.timestamp char array ---
void getTimestamp()
{
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo))
  {
    strncpy(current_data.timestamp, "NTP Sync Failed", TIMESTAMP_SIZE);
    current_data.timestamp[TIMESTAMP_SIZE - 1] = '\0';
    return;
  }
  // Use strftime to write directly to the char array
  strftime(current_data.timestamp, TIMESTAMP_SIZE, "%H:%M:%S", &timeinfo);
}  // <-- END of getTimestamp()

// ----------------------------------------------------
// --- MQTT FUNCTIONS (UPDATED FOR C-STRINGS) ---
// ----------------------------------------------------

// This is a single, non-blocking attempt to connect. (Unmodified)
void reconnectMQTT()
{
  if (WiFi.status() != WL_CONNECTED)
  {
    // Don't even try if Wi-Fi is down
    return;
  }

  Serial.print("Attempting MQTT connection (Single attempt)...");
  // Try to connect once
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
}  // <-- END of reconnectMQTT()


// new function to breakdown MQTT (now accepts unit) - MODIFIED
void publishMQTTSimpleValue(const char* topicSuffix, float value, int precision, const char* unit)
{
  if (!mqttClient.connected())
  {
    Serial.println("Publish failed: MQTT not connected.");
    return;
  }

  // Use local char arrays instead of String for topic and payload
  char fullTopic[64];
  char floatPayload[10];
  char textPayload[64]; 
  
  // Construct the full topic using snprintf
  snprintf(fullTopic, sizeof(fullTopic), "home/blue_gate/%s", topicSuffix);

  // Convert the float value to a string
  dtostrf(value, 0, precision, floatPayload);

  // --- CONSTRUCT THE FINAL, NON-GRAPHABLE TEXT STRING using snprintf ---
  snprintf(textPayload, sizeof(textPayload), "%s: %s %s", topicSuffix, floatPayload, unit);

  Serial.printf("Publishing to %s: %s\n", fullTopic, textPayload);

  mqttClient.publish(fullTopic, textPayload, false);  // Publish as text
}  // <-- END of publishMQTTSimpleValue()


void publishMQTTEvent() // MODIFIED
{
  if (!mqttClient.connected())
  {
    Serial.println("Publish failed: MQTT not connected.");
    return;
  }

  // --- 1. Publish MAIN Status (JSON) ---
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
  // serializeJson handles c-strings automatically
  serializeJson(doc, jsonBuffer);

  Serial.print("Publishing JSON to MQTT topic ");
  Serial.print(MQTT_TOPIC_STATUS);
  Serial.print(": ");
  Serial.println(jsonBuffer);

  // Publish main status topic (retained=true for current state)
  mqttClient.publish(MQTT_TOPIC_STATUS, jsonBuffer, true);

  // --- 2. Publish Metric Topics (Only if data is valid) ---
  if (current_data.data_valid)
  {
    publishMQTTSimpleValue("RSSI_dBm", current_data.rssi_dbm, 1, "dBm");
    publishMQTTSimpleValue("battery_V", current_data.batt_voltage, 2, "V");
  }

}  // <-- END of publishMQTTEvent()


// ----------------------------------------------------
// --- PUSHOVER FUNCTIONS (UPDATED FOR C-STRINGS) ---
// ----------------------------------------------------

void sendPushover()
{
  Serial.println("Attempting Pushover notification...");

  secureClient.setInsecure();

  HTTPClient http;

  // --- REPLACED: Build URL using char array and snprintf ---
  char url[URL_BUF_SIZE];
  snprintf(url, sizeof(url), "https://%s/1/messages.json", PUSHOVER_HOST);
  
  http.begin(secureClient, url);
  // --------------------------------------------------------
  
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");

  // *** WDT SAFETY: Set an explicit timeout shorter than the 5s WDT. ***
  http.setTimeout(4000); // 4 seconds timeout for the blocking HTTP POST

  // --- START: NEW SINGLE-LINE MESSAGE CONSTRUCTION (C-STRINGS) ---
  char messageContent[MESSAGE_BUF_SIZE];
  const char* statusPrefix = (strcmp(current_data.status, "OPEN") == 0) ? "Blue Gate OPEN @ " : "Blue Gate CLOSED @ ";

  // Use snprintf to build the message body safely
  snprintf(messageContent, sizeof(messageContent), 
           "%s%s %.1f dBm %s (%.2f V)",
           statusPrefix,
           current_data.timestamp,
           current_data.rssi_dbm,
           current_data.batt_ok ? "OK" : "LOW",
           current_data.batt_voltage);
  // --- END: NEW SINGLE-LINE MESSAGE CONSTRUCTION ---

  // --- URL ENCODE THE MESSAGE CONTENT ---
  char encodedMessage[POSTDATA_BUF_SIZE]; // Use a large buffer for the encoded message
  urlEncode(messageContent, encodedMessage, sizeof(encodedMessage));


  // --- BUILD THE FINAL POST DATA (C-STRINGS) ---
  char postData[POSTDATA_BUF_SIZE];
  int len = 0;
  
  // Token
  len += snprintf(postData + len, sizeof(postData) - len, "token=%s", PUSHOVER_TOKEN);
  
  // User
  len += snprintf(postData + len, sizeof(postData) - len, "&user=%s", PUSHOVER_USER);
  
  // Device
  len += snprintf(postData + len, sizeof(postData) - len, "&device=%s", PUSHOVER_DEVICE);
  
  // Message (Encoded)
  len += snprintf(postData + len, sizeof(postData) - len, "&message=%s", encodedMessage);

  Serial.printf("Pushover Data Includes Device: %s\n", PUSHOVER_DEVICE);
  Serial.printf("Pushover Post Data Length: %d\n", len);

  // POST the data and get the response code
  // http.POST takes a const char* (C-string) directly
  int httpResponseCode = http.POST(postData);

  if (httpResponseCode == 200)
  {  // Check specifically for 200 OK
    Serial.printf("Pushover success! Response Code: %d\n", httpResponseCode);
    
    // --- RED FLASH TRIGGER: NOW NON-BLOCKING! ---
    Serial.println("--- INITIATING FLASH 2 (Red PO CONFIRM) ---");
    initBlink(LED_DRIVER_B, LED_DRIVER_A);
    // ------------------------------------------

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
}  // <-- END of sendPushover()


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
} // <-- END of blinkHandler()


// ----------------------------------------------------
// --- NON-BLOCKING NETWORK MANAGEMENT (Unmodified) ---
// ----------------------------------------------------

void checkAndReconnectNetwork()
{
  unsigned long currentMillis = millis();

  // Condition 1: If we are currently in local mode OR MQTT is disconnected
  if (!is_online_mode || !mqttClient.connected()) 
  {
    // Condition 2: If the reconnection interval has passed since the last attempt
    if (currentMillis - last_reconnect_attempt_ms >= RECONNECT_INTERVAL_MS)
    {
      Serial.println("\n--- Non-Blocking Reconnection Attempt Triggered ---");
      last_reconnect_attempt_ms = currentMillis; // Reset the timer immediately

      // --- 1. Attempt Wi-Fi Reconnect (if needed) ---
      if (WiFi.status() != WL_CONNECTED)
      {
        Serial.print("Attempting Wi-Fi reconnect...");
        WiFi.reconnect();
      }
      
      // --- 2. Attempt MQTT Reconnect (if Wi-Fi is connected) ---
      if (WiFi.status() == WL_CONNECTED && !mqttClient.connected())
      {
        reconnectMQTT(); // Single, non-blocking attempt
      }
      
      // --- 3. Update the global online state ---
      bool was_online_mode = is_online_mode;
      is_online_mode = (WiFi.status() == WL_CONNECTED && mqttClient.connected());
      
      if (is_online_mode && !was_online_mode) 
      {
         Serial.println("Successfully reconnected to network and MQTT. ONLINE MODE restored.");
         configTime(0, 0, "pool.ntp.org");
         // --- SUCCESS: RESET FAILURE COUNT ---
         reconnect_fail_count = 0;
      } 
      else if (was_online_mode && !is_online_mode) 
      {
         Serial.println("WARNING: Lost network connection. Falling back to LOCAL MODE.");
         // --- FAILURE: INCREMENT FAILURE COUNT ---
         reconnect_fail_count++;
      } 
      else if (!is_online_mode)
      {
         // --- FAILURE: INCREMENT FAILURE COUNT for continued failure ---
         reconnect_fail_count++;
         Serial.printf("Reconnection attempt done. Current mode: LOCAL. Failure count: %d/%d\n", 
                        reconnect_fail_count, MAX_RECONNECT_FAILURES);

         // --- CRITICAL: CHECK FOR REBOOT CONDITION ---
         if (reconnect_fail_count >= MAX_RECONNECT_FAILURES)
         {
           Serial.println("\n!!! MAX RECONNECT FAILURES REACHED !!! Initiating ESP32 Hard Reset.");
           // This is the correct function call for an ESP32 software reboot:
           ESP.restart(); 
           delay(500); // Give time for serial output before reset
         }
      }
    }
  }
  else
  {
      // If we are currently ONLINE, ensure the flag reflects the true state (paranoia check)
      if (WiFi.status() != WL_CONNECTED || !mqttClient.connected()) {
          // A break was detected outside the timer window. Set flag to false, next loop will re-check time.
          is_online_mode = false;
          reconnect_fail_count++; // Increment count as connection was lost outside the timer interval
      } else {
          // If we are online, ensure the counter is 0
          reconnect_fail_count = 0;
      }
  }
} // <-- END of checkAndReconnectNetwork()


// ----------------------------------------------------
// --- SETUP and LOOP (Updated for C-Strings) ---
// ----------------------------------------------------

void setup()
{
  // --- PHASE 1, RANK 1 FIX: CHANGED 115700 TO 115200 (Assumed) ---
  Serial.begin(115200);

  Serial.println("\n--- Starting Dual-Input Gate Alert System ---");

  // -----------------
  // --- WDT SETUP ---
  // -----------------
  const esp_task_wdt_config_t wdt_config = {
    WDT_TIMEOUT_SEC,                     // Timeout in seconds
    (1 << CONFIG_ARDUINO_RUNNING_CORE),  // idle_core_mask
    true                                 // trigger_panic
  };

  esp_task_wdt_init(&wdt_config);

  // Add the current running task (the loop task) to the WDT list
  esp_task_wdt_add(NULL);

  Serial.printf("Task Watchdog Timer enabled with %d second timeout.\n", WDT_TIMEOUT_SEC);
  // -----------------

  Serial2.begin(BAUD_RATE, SERIAL_8N1, SERIAL_RX_PIN, SERIAL_TX_PIN);

  // 1. GPIO Setup
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(SENSOR_PIN, INPUT_PULLUP);
  // --- NEW LED SETUP (BI-COLOUR) ---
  pinMode(LED_DRIVER_A, OUTPUT);
  pinMode(LED_DRIVER_B, OUTPUT);
  digitalWrite(LED_DRIVER_A, LOW);
  digitalWrite(LED_DRIVER_B, LOW);

  // Initial state reading (Redundant but harmless)
  isr_button_state = digitalRead(BUTTON_PIN);
  isr_sensor_state = digitalRead(SENSOR_PIN);

  Serial.printf("Built-in Button Pin: GPIO %d\n", BUTTON_PIN);
  Serial.printf("External Sensor Pin: GPIO %d\n", SENSOR_PIN);


  // 3. Wi-Fi Connection & NTP Setup (WDT Protected & Blocking Startup)
  Serial.print("Attempting to connect to WiFi...");

  // 3. Wi-Fi Connection & NTP Setup (NOW NON-BLOCKING)
  Serial.print("Starting Wi-Fi connection (non-blocking)...");

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD); 
  Serial.println("Wi-Fi process started.");

  // 4. MQTT Setup
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  
  // NOTE: We don't attempt to connect Wi-Fi or MQTT here. 
  // We rely entirely on checkAndReconnectNetwork() in the loop().

  // --- INITIALIZE NETWORK STATE AFTER NON-BLOCKING START ---
  is_online_mode = false;
  
  // Initialize the timer so the first non-blocking check happens right away
  last_reconnect_attempt_ms = millis() - RECONNECT_INTERVAL_MS; 
  Serial.println("System starting in LOCAL MODE. Network checks begin in loop().");
  
  // --- NEW: INITIALIZE NETWORK STATE AFTER SETUP ATTEMPTS ---
  if (WiFi.status() == WL_CONNECTED && mqttClient.connected()) 
  {
      is_online_mode = true;
      Serial.println("System starting in ONLINE MODE.");
  }
  else
  {
      is_online_mode = false;
      Serial.println("System starting in LOCAL MODE.");
  }
  // Initialize the timer so the first non-blocking check happens after RECONNECT_INTERVAL_MS
  last_reconnect_attempt_ms = millis(); 
  // ---------------------------------------------------------


  // ------------------------------------
  // --- CRITICAL FIX: DEFER INTERRUPT ATTACHMENT ---
  Serial.println("Waiting 1 second for external hardware stabilization...");
  delay(1000);

  // 2. Attach Interrupts (NOW DEFERRED)
  attachInterrupt(digitalPinToInterrupt(BUTTON_PIN), handleGateInterrupt, CHANGE);
  Serial.printf("Interrupt attached to Button (GPIO %d).\n", BUTTON_PIN);

  attachInterrupt(digitalPinToInterrupt(SENSOR_PIN), handleGateInterrupt, CHANGE);
  Serial.printf("Interrupt attached to Sensor (GPIO %d).\n", SENSOR_PIN);

  // --- CRITICAL FIX: RE-READ BASELINE STATE HERE ---
  isr_button_state = digitalRead(BUTTON_PIN);
  isr_sensor_state = digitalRead(SENSOR_PIN);
  Serial.println("Initial stable pin states re-read.");
  // ------------------------------------

}  // <-- END of setup()

void loop()
{
  // --- WDT RESET (FEEDING THE DOG) ---
  esp_task_wdt_reset();
  
  // --- NON-BLOCKING LED BLINK HANDLER ---
  blinkHandler();

  // --- NON-BLOCKING NETWORK MANAGEMENT ---
  checkAndReconnectNetwork();

  // --- CHECK 1: Keep the MQTT connection alive (only if online)
  if (is_online_mode)
  {
    mqttClient.loop();
  }

  // Process one queued event per loop iteration if available
  if (queue_head != queue_tail)
  {

    // --- READ EVENT FROM QUEUE ---
    Event next_event;
    // Safely copy the volatile structure using memcpy
    memcpy(&next_event, (const void*)&event_queue[queue_tail], sizeof(Event));

    // Advance the tail pointer (consumes the event)
    queue_tail = (queue_tail + 1) % MAX_QUEUE_SIZE;

    Serial.println("--- Gate Event Fired (Main Loop - From Queue) ---");

    // =======================================================
    // --- CAPTURE TIMESTAMP HERE (NOW WRITING TO CHAR ARRAY) ---
    // =======================================================
    if (WiFi.status() == WL_CONNECTED)
    {
      getTimestamp(); // Writes directly to current_data.timestamp
    }
    else
    {
      strncpy(current_data.timestamp, "LOCAL TIME UNKNOWN", TIMESTAMP_SIZE);
      current_data.timestamp[TIMESTAMP_SIZE - 1] = '\0';
    }
    Serial.printf("Captured Timestamp: %s\n", current_data.timestamp);
    // =======================================================


    // --- ASSIGN STATUS & SOURCE (NOW USING C-STRING COPY) ---
    strncpy(current_data.status, next_event.status, STATUS_SIZE);
    current_data.status[STATUS_SIZE - 1] = '\0'; // Ensure termination

    Serial.printf("Trigger Source: %s - ", next_event.source);

    // --- Execute Action ---

    Serial.printf("Detected State: %s\n", current_data.status);

    // Read data from the Gamma62T module
    if (readGammaData())
    {
      parseGammaData();

      // --- SYNCHRONOUS GREEN FLASH (RX Confirm) - NOW NON-BLOCKING ---
      Serial.println("--- INITIATING FLASH 1 (Green RX) ---");
      initBlink(LED_DRIVER_A, LED_DRIVER_B);
      // -----------------------------------------------------------------
    }
    else
    {
      current_data.data_valid = false;
      current_data.rssi_dbm = 0.0;
      current_data.batt_voltage = 0.0;
      current_data.batt_ok = false;
    }

    // --- START: MODIFIED NOTIFICATION LOGIC FOR ROBUSTNESS ---

    if (WiFi.status() == WL_CONNECTED)
    {
      Serial.println("WiFi connected. Attempting notifications...");

      // Pushover only requires Wi-Fi/Internet, so it runs first
      sendPushover(); // Runs the blocking HTTP call

      // MQTT requires Wi-Fi AND a successful broker connection check (is_online_mode)
      if (is_online_mode) 
      {
        publishMQTTEvent();
      }
      else
      {
         Serial.println("MQTT publication skipped (MQTT DOWN or initial attempt failed).");
      }
    }
    else
    {
      Serial.println("No WiFi connection. Notifications skipped (LOCAL MODE).");
    }

    // --- END: MODIFIED NOTIFICATION LOGIC FOR ROBUSTNESS ---

    Serial.println("--- Event Handled ---\n");
  }

  // Small delay to prevent a busy loop
  delay(10);
}  // <-- END of loop()
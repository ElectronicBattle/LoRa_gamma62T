// DFRobot FireBeetle 2 ESP32-E (DFR0654) - IoT Gate Alert System
// Includes WDT stability, interrupt queueing, serial sync
// non-blocking network logic, and power-up stabilization fixes
// Green Flash is Sync (serial RX Confirm). Red Flash is ASYNC (Pushover 200 OK Confirm)
// 4 second HTTP Timeout in sendPushover() for WDT safety
// Added Non-Blocking Network Reconnection Logic
// Timestamp capture moved for closer alignment with event trigger
// ALL OK for "production" 22/11/25
// starting to add duck.ai recommended improvements beginning with
// correcting the serial rate from 115700 to 115200

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <string.h>  // For interrupt-safe strcpy/memcpy
#include <secrets.h> // stored at ~/Arduino/libraries/secrets/secrets.h

// --- WDT HEADER ---
#include "esp_task_wdt.h"
// ------------------

// --- FIX: ADD FUNCTION PROTOTYPES FOR LINKER ERROR ---
void setup();
void loop();
void reconnectMQTT();
void checkAndReconnectNetwork();
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


// ----------------------------------------------------
// --- GLOBAL OBJECTS & EVENT QUEUE ---
// ----------------------------------------------------

WiFiClient espClient;
WiFiClientSecure secureClient;
PubSubClient mqttClient(espClient);

// --- GLOBAL VARIABLES FOR NON-BLOCKING RECONNECT ---
// Try to reconnect every 2 minutes (120,000 ms) if Wi-Fi or MQTT is lost.
const unsigned long RECONNECT_INTERVAL_MS = 5000; 
unsigned long last_reconnect_attempt_ms = 0;
bool is_online_mode = false; // Tracks current operating mode (Wi-Fi AND MQTT connected)
// ----------------------------------------------------

// --- NEW AUTO-REBOOT COUNTER ---
const int MAX_RECONNECT_FAILURES = 10;
int reconnect_fail_count = 0; 
// ----------------------------------------------------


// Structure to store a single event (using char arrays for interrupt safety)
struct Event
{
  char status[10];
  char source[10];
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

// Structure to hold all status data for transmission
struct GateData
{
  String timestamp;
  String status;
  float rssi_dbm = 0.0;
  float batt_voltage = 0.0;
  bool batt_ok = false;
  bool data_valid = false;
} current_data;


// ----------------------------------------------------
// --- INTERRUPT HANDLER ---
// ----------------------------------------------------

// void IRAM_ATTR handleGateInterrupt()
// {
//   unsigned long interrupt_time = millis();

//   int current_btn = digitalRead(BUTTON_PIN);
//   int current_sensor = digitalRead(SENSOR_PIN);

//   if (interrupt_time - last_interrupt_time > DEBOUNCE_DELAY_MS)
//   {

//     bool btn_changed = (current_btn != isr_button_state);
//     bool sensor_changed = (current_sensor != isr_sensor_state);

//     if (btn_changed || sensor_changed)
//     {

//       if (((queue_head + 1) % MAX_QUEUE_SIZE) != queue_tail)
//       {

//         const char* new_status;
//         const char* new_source;

//         if (sensor_changed)
//         {
//           new_status = (current_sensor == LOW) ? "OPEN" : "CLOSED";
//           new_source = "SENSOR";
//         }
//         else if (btn_changed)
//         {
//           new_status = (current_btn == LOW) ? "CLOSED" : "OPEN";
//           new_source = "BUTTON";
//         }

//         // Push Event onto Queue using strcpy
//         strcpy((char*)event_queue[queue_head].status, new_status);
//         strcpy((char*)event_queue[queue_head].source, new_source);

//         queue_head = (queue_head + 1) % MAX_QUEUE_SIZE;

//         last_interrupt_time = interrupt_time;
//         isr_button_state = current_btn;
//         isr_sensor_state = current_sensor;
//       }
//     }
//   }
// }

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

        // --- NEW: Push Event onto Queue using strncpy for safety ---
        volatile Event* current_event = &event_queue[queue_head];
        const size_t STATUS_SIZE = sizeof(current_event->status);
        const size_t SOURCE_SIZE = sizeof(current_event->source);

        // Copy Status (max 9 chars + null terminator)
        strncpy((char*)current_event->status, new_status, STATUS_SIZE - 1);
        // Explicitly set the last character to null to ensure termination
        current_event->status[STATUS_SIZE - 1] = '\0'; 

        // Copy Source (max 9 chars + null terminator)
        strncpy((char*)current_event->source, new_source, SOURCE_SIZE - 1);
        // Explicitly set the last character to null to ensure termination
        current_event->source[SOURCE_SIZE - 1] = '\0';
        // -----------------------------------------------------------

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

// --- OPTIMIZED urlEncode() FUNCTION (Faster C-string logic) ---
String urlEncode(String str)
{
  // Buffer size set large enough for safety. Max 3x original length plus null terminator.
  const int BUF_SIZE = 256; 
  char encoded_buffer[BUF_SIZE]; 
  int encoded_index = 0;

  for (int i = 0; i < str.length() && encoded_index < BUF_SIZE - 4; i++) 
  {
    char c = str.charAt(i);
    
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      encoded_buffer[encoded_index++] = c;
    }
    else if (c == ' ')
    {
      encoded_buffer[encoded_index++] = '+';
    }
    else
    {
      // URL encode using hex values
      encoded_buffer[encoded_index++] = '%';
      
      char code1 = (c >> 4) & 0xF;
      char code0 = c & 0xF;
      
      encoded_buffer[encoded_index++] = (code1 < 10) ? (char)(code1 + '0') : (char)(code1 - 10 + 'A');
      encoded_buffer[encoded_index++] = (code0 < 10) ? (char)(code0 + '0') : (char)(code0 - 10 + 'A');
    }
  }
  encoded_buffer[encoded_index] = '\0'; // Null-terminate the string

  return String(encoded_buffer);
}


// Attempts to read the full 10-byte packet from Serial2 (Gamma62T) with CR/LF Synchronization
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

void parseGammaData()
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

String getTimestamp()
{
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo))
  {
    return "NTP Sync Failed";
  }
  char timeStr[64];
  strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &timeinfo);
  return String(timeStr);
}  // <-- END of getTimestamp()

// ----------------------------------------------------
// --- MQTT FUNCTIONS (Single Attempt) ---
// ----------------------------------------------------

// This is a single, non-blocking attempt to connect.
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


// new function to breakdown MQTT (now accepts unit)
void publishMQTTSimpleValue(const char* topicSuffix, float value, int precision, const char* unit)
{
  if (!mqttClient.connected())
  {
    // Do not attempt a reconnect here; let the loop() logic manage connection state.
    Serial.println("Publish failed: MQTT not connected.");
    return;
  }

  // Construct the full topic
  String fullTopic = "home/blue_gate/";
  fullTopic.concat(topicSuffix);

  // Convert the float value to a string
  char floatPayload[10];
  dtostrf(value, 0, precision, floatPayload);

  // --- CONSTRUCT THE FINAL, NON-GRAPHABLE TEXT STRING ---
  String textPayload = String(topicSuffix);
  textPayload.concat(": ");
  textPayload.concat(floatPayload);
  textPayload.concat(" ");
  textPayload.concat(unit);

  Serial.printf("Publishing to %s: %s\n", fullTopic.c_str(), textPayload.c_str());

  mqttClient.publish(fullTopic.c_str(), textPayload.c_str(), false);  // Publish as text
}  // <-- END of publishMQTTSimpleValue()


void publishMQTTEvent()
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
// --- PUSHOVER FUNCTIONS ---
// ----------------------------------------------------

void sendPushover()
{
  Serial.println("Attempting Pushover notification...");

  secureClient.setInsecure();

  HTTPClient http;

  // --- FIX APPLIED HERE: Build URL safely using String concatenation ---
  String url = "https://";
  url += PUSHOVER_HOST;
  url += "/1/messages.json";
  
  http.begin(secureClient, url);
  // --------------------------------------------------------------------
  
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");

  // *** WDT SAFETY: Set an explicit timeout shorter than the 5s WDT. ***
  http.setTimeout(4000); // 4 seconds timeout for the blocking HTTP POST

  String status = (current_data.status == "OPEN") ? "Blue Gate OPEN @ " : "Blue Gate CLOSED @ ";

  // --- START: NEW SINGLE-LINE MESSAGE CONSTRUCTION ---
  String messageContent = status;

  messageContent.reserve(100); // Reserve memory for the maximum possible message length
  
  messageContent += current_data.timestamp;

  // Append RSSI data: " -62.0 dBm"
  messageContent += " ";
  messageContent += String(current_data.rssi_dbm, 1);
  messageContent += " dBm";

  // Append Battery data: " OK (2.60 V)"
  messageContent += " ";
  messageContent += (current_data.batt_ok ? "OK" : "LOW");
  messageContent += " (";
  messageContent += String(current_data.batt_voltage, 2);
  messageContent += " V)";
  // --- END: NEW SINGLE-LINE MESSAGE CONSTRUCTION ---

  String postData = "token=";
  postData.concat(PUSHOVER_TOKEN);
  postData.concat("&user=");
  postData.concat(PUSHOVER_USER);
  postData.concat("&device=");
  postData.concat(PUSHOVER_DEVICE);
  postData.concat("&message=");

  postData.concat(urlEncode(messageContent));

  Serial.printf("Pushover Data Includes Device: %s\n", PUSHOVER_DEVICE);

  // POST the data and get the response code
  int httpResponseCode = http.POST(postData);

  if (httpResponseCode == 200)
  {  // Check specifically for 200 OK
    Serial.printf("Pushover success! Response Code: %d\n", httpResponseCode);
    
    // --- RED FLASH TRIGGER: ONLY on 200 OK (ASYNC CONFIRMATION) ---
    Serial.println("--- FLASH 2 (Red PO CONFIRM) ---");
    // Use DRIVER B as Source, DRIVER A as Sink
    digitalWrite(LED_DRIVER_A, LOW);  //16
    digitalWrite(LED_DRIVER_B, HIGH); //14
    delay(FLASH_DURATION_MS); // 100ms ON
    digitalWrite(LED_DRIVER_A, LOW);
    digitalWrite(LED_DRIVER_B, LOW); // Turn off Red immediately
    // ----------------------------------------------------

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
// --- NON-BLOCKING NETWORK MANAGEMENT ---
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
// --- SETUP and LOOP ---
// ----------------------------------------------------

void setup()
{
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

  // Set a timeout for 10 seconds (20 attempts * 500ms)
  const int maxAttempts = 20;
  int attemptCount = 0;

  // 3. Wi-Fi Connection & NTP Setup (NOW NON-BLOCKING)
  Serial.print("Starting Wi-Fi connection (non-blocking)...");

  // We do NOT disable/re-enable the WDT here. We must keep it running.
  // The built-in Wi-Fi logic is designed to work alongside the WDT.
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD); 
  Serial.println("Wi-Fi process started.");

  // 4. MQTT Setup
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  
  // NOTE: We don't attempt to connect Wi-Fi or MQTT here. 
  // We rely entirely on checkAndReconnectNetwork() in the loop().

  // --- INITIALIZE NETWORK STATE AFTER NON-BLOCKING START ---
  // The first checkAndReconnectNetwork() will run immediately in the loop()
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
  // This must be called regularly to prevent a WDT reboot.
  esp_task_wdt_reset();

  // --- NEW: NON-BLOCKING NETWORK MANAGEMENT ---
  checkAndReconnectNetwork();

  // --- CHECK 1: Keep the MQTT connection alive (only if online)
  if (is_online_mode)
  {
    // PubSubClient's loop() handles pinging the broker and receiving data.
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
    // --- FIX: CAPTURE TIMESTAMP HERE (AS EARLY AS POSSIBLE) ---
    // Change logic: Time is available if WiFi is up, regardless of MQTT.
    // =======================================================
    if (WiFi.status() == WL_CONNECTED)
    {
      current_data.timestamp = getTimestamp();
    }
    else
    {
      // If WiFi itself is down (true local mode), we cannot get time.
      current_data.timestamp = "LOCAL TIME UNKNOWN";
    }
    Serial.printf("Captured Timestamp: %s\n", current_data.timestamp.c_str());
    // =======================================================


    // --- ASSIGN STATUS & SOURCE ---
    current_data.status = String(next_event.status);

    Serial.printf("Trigger Source: %s - ", next_event.source);

    // --- Execute Action ---

    Serial.printf("Detected State: %s\n", current_data.status.c_str());

    // Read data from the Gamma62T module
    if (readGammaData())
    {
      parseGammaData();

      // -----------------------------------------------------------------
      // --- SYNCHRONOUS GREEN FLASH (RX Confirm) ---
      // This confirms successful data decode.
      // -----------------------------------------------------------------

      // 1. FLASH 1: RX CONFIRM (Green - assumed GPIO 16 HIGH / DRIVER A HIGH)
      Serial.println("--- FLASH 1 (Green RX) ---");
      // Use DRIVER A as Source, DRIVER B as Sink
      digitalWrite(LED_DRIVER_B, LOW);
      digitalWrite(LED_DRIVER_A, HIGH); 
      delay(FLASH_DURATION_MS); // 100ms ON

      // 2. Turn OFF Green immediately to start the network latency gap
      digitalWrite(LED_DRIVER_A, LOW);
      digitalWrite(LED_DRIVER_B, LOW);
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
      // This MUST run if Wi-Fi is connected, regardless of MQTT status.
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
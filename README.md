# LoRa_gamma62T_9_FINAL
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

// Final Stable Version: Secure TLS, Non-Blocking, and Flash Optimized.

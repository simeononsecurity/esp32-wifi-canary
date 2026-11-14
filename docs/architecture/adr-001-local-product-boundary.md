# ADR 001: local WiFi-awareness product boundary

Status: accepted for this productization branch.

WiFi Canary keeps one WiFi detection core across board profiles. Hardware adapters only present state and accept local button input.

Configuration and scored history use dedicated flash partitions. The detector stays offline. A static browser client handles flashing and dashboards through USB. Host tools handle multiple serial units.

Rejected options include hosting a dashboard on the detector, joining an access point, remote telemetry, unrelated detection engines, and production transmitter test paths.

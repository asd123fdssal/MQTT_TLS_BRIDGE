# MQTT TLS Bridge

A Windows WPF utility that combines:

- an **MQTTS broker** (server) for test purposes, and
- an **MQTT client** (connect / subscribe / publish),
  plus a lightweight **TCP control server** (INI-style packets) to automate the UI from external test tools.

Target use case: MQTT/TLS interoperability testing (TLS 1.3 / 1.2), certificate validation scenarios, and scripted automation of broker/client flows.

---

## Tech Stack

- **.NET**: net10.0-windows
- **UI**: WPF + WPF-UI / WPF-UI.Tray
- **MQTT**: MQTTnet + MQTTnet.Server
- **MVVM helpers**: CommunityToolkit.Mvvm

---

## Features

### Client (MQTT)

- Connect to an MQTT broker with optional TLS
- Subscribe / Unsubscribe with QoS
- Publish with QoS and Retain
- TLS protocol selection:
  - TLS 1.3
  - TLS 1.2
  - TLS 1.3 + 1.2

### TLS Certificate Validation Modes (Client)

- **Strict**: OS trust, no SSL policy errors
- **Allow Untrusted**: accept any certificate
- **Custom CA (file)**: validate using a custom root store
- **Thumbprint Pinning**: validate by certificate thumbprint

### Broker (MQTTS Server)

- Start / Stop an encrypted MQTT broker
- Uses PFX (PKCS#12) certificate
- TLS protocol selection (1.3 / 1.2 / both)

### Control Server (Automation)

- Built-in TCP server (default port **4811**)
- INI-style key=value packets
- Can drive broker and client actions programmatically

### Tray Behavior

- Closing the window hides the app to the system tray
- Tray menu: Open / Exit
- Double-click tray icon opens the window

### Logging

- UI logs for client and broker events
- File logging under:
  - .\Logs\ (daily log files)
  - raw control packets (RX / TX)

---

## Requirements

- Windows
- .NET SDK supporting net10.0-windows
- Visual Studio with WPF workload (recommended)

---

## Build & Run

1. Open the solution in Visual Studio
2. Build and run the `MQTT_TLS_Bridge` project

---

## Settings

- Stored in `.\Config\settings.json`
- If **Save passwords** is disabled, passwords are not persisted

---

## Control Server Protocol

### Transport

- TCP
- Default port: 4811
- Binds to Loopback or IPAddress.Any (if Allow Remote enabled)

### Packet Format (Request)

- UTF-8 text
- key=value per line
- Blank line terminates packet
- Lines starting with `;` or `#` are ignored

Example:

```ini
id=1
cmd=client.connect
host=127.0.0.1
port=8883
useTls=1
tls=13
```

### Packet Format (Response)

- key=value lines followed by a blank line

#### Always includes

- id=<same id>
- ok=1 on success, ok=0 on failure

#### On failure also includes

- err=<error code>
- msg=<message>

Example (success):

```ini
id=1
ok=1
state=connected
```

Example (failure):

```ini
id=1
ok=0
err=Timeout
msg=connect timeout (10000ms)
```

---

## Supported Control Commands

### broker.start

Starts the built-in MQTTS broker.

Args:

- port (optional; falls back to UI)
- pfx (optional; falls back to UI; required overall)
- pfxpw (optional; falls back to UI)
- tls (optional; values: 13, 12, 12|13)

Response:

- running=1

Example:

```ini
id=10
cmd=broker.start
port=8883
pfx=cert\devcert.pfx
pfxpw=yourPassword
tls=13
```

---

### broker.stop

Stops the broker.

Response:

- running=0

---

### client.connect

Connects the built-in MQTT client.

Args (all optional unless noted):

- host
- port
- clientId
- username
- password
- useTls (1/0)
- allowUntrusted (1/0)
- tls (13, 12, 12|13)
- timeoutMs (default 10000)

Response:

- state=connected

---

### client.disconnect

Disconnects the client.

Response:

- state=disconnected

---

### client.publish

Publishes a message.

Args:

- topic (required)
- qos (0|1|2)
- retain (1/0)
- payload (plain text)
- payload_b64 (base64, takes precedence)

Example:

```ini
id=20
cmd=client.publish
topic=test/topic
payload=hello
```

---

### client.subscribe

Subscribes to a topic filter.

Args:

- filter (required)
- qos (0|1|2)

---

### client.unsubscribe

Unsubscribes from a topic filter.

Args:

- filter (required)

---

## Notes / Caveats

- Broker binds to IPAddress.Any; firewall rules may apply
- Certificate thumbprints are normalized before comparison
- Closing the window hides the app to tray unless exited explicitly

---

## Project Structure

- Broker/     – MQTT server wrapper
- Publisher/  – MQTT client wrapper
- Control/    – TCP control server and INI parser
- Settings/   – settings.json storage
- Logging/    – daily file logs
- MainWindow.* – UI orchestration
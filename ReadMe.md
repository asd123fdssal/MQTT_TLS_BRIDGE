<p align="center">
  <strong>MQTT TLS Bridge</strong><br/>
  MQTT/TLS testing utility with embedded broker, client, and automation control
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#control-server-protocol">Control Protocol</a> •
  <a href="#troubleshooting">Troubleshooting</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-net10.0--windows-512BD4" />
  <img src="https://img.shields.io/badge/MQTT-MQTTnet-blue" />
  <img src="https://img.shields.io/badge/TLS-1.2%20%7C%201.3-green" />
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey" />
</p>


A Windows WPF utility that combines:

- an **MQTTS broker** (server) for test purposes, and
- an **MQTT client** (connect / subscribe / publish),
  plus a lightweight **TCP control server** (INI-style packets) to automate the UI from external test tools.

Target use case: MQTT/TLS interoperability testing (TLS 1.3 / 1.2), certificate validation scenarios, and scripted automation of broker/client flows.

---
## 📚 Contents
- [Quick Start](#quick-start)
- [Features](#features)
- [Control Server Protocol](#control-server-protocol)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
---

## Quick Start

This section provides minimal, working examples to verify that the broker,
client, and control server are functioning correctly.
No prior knowledge of the internal architecture is required.

---

### Quick Start – Broker Only (TLS 1.3)

This scenario starts the embedded MQTTS broker and waits for incoming TLS
connections.

1. Prepare a PFX certificate file  
   Example path: `cert\devcert.pfx`

2. Configure the broker settings in the UI
   - Broker port: `8883`
   - TLS protocol: `1.3`
   - PFX path and password

3. Start the broker using the control server

Example request:

```ini
id=1
cmd=broker.start
port=8883
pfx=cert\devcert.pfx
pfxpw=yourPassword
tls=13
```

Expected response:

```ini
id=1
ok=1
running=1
```

At this point, the embedded MQTTS broker is listening for TLS connections.

### Quick Start – Client to External Broker

This scenario connects the built-in MQTT client to an external broker,
subscribes to a topic, and publishes a test message.

1. Connect the client

```ini
id=2
cmd=client.connect
host=127.0.0.1
port=8883
useTls=1
tls=13
allowUntrusted=1
```

Expected response:

```ini
id=2
ok=1
state=connected
```

2. Subscribe to a topic

```ini
id=3
cmd=client.subscribe
filter=test/topic
qos=1
```

3. Publish a message

```ini
id=4
cmd=client.publish
topic=test/topic
payload=hello mqtt
```

If the broker echoes the message back to subscribed clients,
the client connection is working correctly.

---

### Quick Start – Notes

- The control server expects UTF-8 encoded text

- A blank line terminates each request packet

- The id field is user-defined and echoed in the response

- Commands can be issued while the UI is running or minimized to tray

- Broker and client can be operated independently

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

## Tech Stack

- **.NET**: net10.0-windows
- **UI**: WPF + WPF-UI / WPF-UI.Tray
- **MQTT**: MQTTnet + MQTTnet.Server
- **MVVM helpers**: CommunityToolkit.Mvvm

---


## Control Command Reference (Summary)

This section provides a concise overview of supported control commands.
Detailed argument descriptions and examples are documented in later sections.

|Command|Description|Key Arguments|Notes|
|------|---|---|---|
|broker.start|Start embedded MQTTS broker|port, pfx, pfxpw, tls|PFX required|
|broker.stop|Stop broker|–|Graceful shutdown|
|client.connect|Connect MQTT client|host, port, tls, timeoutMs|TLS optional|
|client.disconnect|Disconnect MQTT client|–|Idempotent|
|client.publish|Publish message|topic, payload, qos, retain|payload_b64 overrides payload|
|client.subscribe|Subscribe to topic filter|filter, qos|QoS 0–2|
|client.unsubscribe|Unsubscribe from topic filter|filter|–|

---

### Payload Handling Rules

This section describes how message payloads are interpreted by the control server.

  - payload_b64 takes precedence over payload

  - payload is treated as UTF-8 plain text

  - Binary payloads should always use payload_b64

  - Empty payloads are allowed

  - If both fields are omitted, an empty payload is published

Example (plain text payload):

```ini
id=20
cmd=client.publish
topic=test/plain
payload=hello world
```

Example (binary payload using base64):

```ini
id=21
cmd=client.publish
topic=test/binary
payload_b64=AAECAwQFBgc=
```

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

---

## Architecture

The following diagrams describe the internal structure,
control flow, and automation model of MQTT TLS Bridge.

### Full Structural Diagram

```mermaid
flowchart LR
  %% External actors
  TT["External Test Tool<br/>(Inspector / Automation)"]:::ext
  MC["External MQTT Client(s)<br/>(optional)"]:::ext
  EB["External MQTT Broker<br/>(optional)"]:::ext

  %% App
  subgraph APP["MQTT TLS Bridge (WPF)"]
    UI["MainWindow<br/>(UI Orchestrator)"]:::core
    CS["TCP Control Server<br/>(INI packets)"]:::core
    BR["MQTTS Broker Service<br/>(MQTTnet.Server)"]:::svc
    CL["MQTT Client Service<br/>(MQTTnet)"]:::svc
    LOG["Logging<br/>(UI + Files)"]:::svc
    SET["Settings Store<br/>(Config/settings.json)"]:::svc

    CS --> UI
    UI --> BR
    UI --> CL
    UI --> LOG
    UI --> SET

    BR --> UI
    CL --> UI
  end

  %% Label nodes (GitHub-safe)
  LCTRL["TCP :4811<br/>INI request/response"]:::note
  LBRK["MQTTS :8883<br/>(optional)"]:::note
  LEB["MQTT/MQTTS"]:::note

  %% Control channel
  TT --- LCTRL --- CS

  %% MQTT channels
  MC --- LBRK --- BR
  CL --- LEB --- EB

  classDef ext fill:#f3f3f3,stroke:#999,color:#111;
  classDef core fill:#e8f0ff,stroke:#4a78ff,color:#111;
  classDef svc fill:#eafff1,stroke:#2fb36d,color:#111;
  classDef note fill:#fff7e6,stroke:#e0a800,color:#111;
```

---

### Control Server Request-Response Sequence

```mermaid
sequenceDiagram
  autonumber
  participant TT as External Test Tool
  participant CS as TCP Control Server
  participant UI as MainWindow
  participant SVC as Broker and Client Services
  participant LOG as Logger

  TT->>CS: Connect TCP 4811
  TT->>CS: Send INI request (id, cmd, args)
  CS->>LOG: Log raw request
  CS->>UI: Dispatch parsed request
  UI->>SVC: Execute command
  SVC-->>UI: Result or error
  UI-->>CS: Build INI response (ok, msg, state)
  CS->>LOG: Log raw response
  CS-->>TT: Send INI response
```

---

### Client Connection Status Diagram

```mermaid
stateDiagram-v2
  [*] --> Disconnected

  Disconnected --> Connecting: client connect
  Connecting --> Connected: connect ok
  Connecting --> Disconnected: connect fail

  Connected --> Disconnecting: client disconnect
  Disconnecting --> Disconnected: disconnect ok

  Connected --> Connected: publish or subscribe
  Connected --> Disconnected: network drop
```

---

### TLS Certificate Verification Mode Determination Flow

```mermaid
flowchart TD
  A["Server certificate presented"]:::core
  B{"allowUntrusted enabled"}:::dec
  OK["ACCEPT"]:::ok
  FAIL["REJECT"]:::fail

  C{"custom CA configured"}:::dec
  D{"chain valid"}:::dec

  E{"thumbprint pinning configured"}:::dec
  F{"thumbprint match"}:::dec

  G["Default OS trust validation"]:::core
  H{"no SSL policy errors"}:::dec

  Y1["Yes"]:::note
  N1["No"]:::note
  Y2["Yes"]:::note
  N2["No"]:::note
  Y3["Yes"]:::note
  N3["No"]:::note
  Y4["Yes"]:::note
  N4["No"]:::note
  Y5["Yes"]:::note
  N5["No"]:::note

  A --> B
  B --> Y1 --> OK
  B --> N1 --> C

  C --> Y2 --> D
  D --> Y3 --> OK
  D --> N3 --> FAIL

  C --> N2 --> E
  E --> Y4 --> F
  F --> Y5 --> OK
  F --> N5 --> FAIL

  E --> N4 --> G
  G --> H
  H --> Y2 --> OK
  H --> N2 --> FAIL

  classDef core fill:#e8f0ff,stroke:#4a78ff,color:#111;
  classDef dec fill:#fff7e6,stroke:#e0a800,color:#111;
  classDef ok fill:#eafff1,stroke:#2fb36d,color:#111;
  classDef fail fill:#ffecec,stroke:#d64545,color:#111;
  classDef note fill:#fff7e6,stroke:#e0a800,color:#111;
```

---

### Test Flow

```mermaid
flowchart LR
  T["Test Script"]:::ext
  TT["External Test Tool"]:::ext
  CS["TCP Control Server"]:::core
  UI["MainWindow"]:::core
  BR["Embedded MQTTS Broker"]:::svc
  CL["Embedded MQTT Client"]:::svc
  DUT["Device Under Test<br/>(MQTT Client)"]:::ext
  LOG["Logs and UI View"]:::svc

  %% Label nodes
  LINI["INI commands"]:::note
  LCMD["broker start<br/>client connect<br/>publish subscribe"]:::note
  LTLS["TLS handshake"]:::note
  LMQTT["MQTT publish and subscribe"]:::note

  T --- LINI --- TT
  TT --- LINI --- CS

  CS --> UI
  UI --- LCMD --- BR
  UI --- LCMD --- CL

  DUT --- LTLS --- BR
  DUT --- LMQTT --- BR

  BR --> LOG
  CL --> LOG

  classDef ext fill:#f3f3f3,stroke:#999,color:#111;
  classDef core fill:#e8f0ff,stroke:#4a78ff,color:#111;
  classDef svc fill:#eafff1,stroke:#2fb36d,color:#111;
  classDef note fill:#fff7e6,stroke:#e0a800,color:#111;
```

---

### Broker Lifecycle diagram

```mermaid
stateDiagram-v2
  [*] --> Stopped

  Stopped --> Starting: broker start
  Starting --> Running: listen ok
  Starting --> Stopped: cert error

  Running --> Stopping: broker stop
  Stopping --> Stopped: stopped

  Running --> Stopped: fatal error
```

The embedded broker has an explicit lifecycle.
All transitions are logged and reflected in the UI state.

---

### Client Lifecycle + Retry Perspective Diagram

```mermaid
stateDiagram-v2
  [*] --> Idle

  Idle --> Connecting: client connect
  Connecting --> Connected: connected
  Connecting --> Idle: timeout

  Connected --> Subscribed: subscribe
  Subscribed --> Connected: unsubscribe

  Connected --> Idle: disconnect
  Connected --> Idle: connection lost
```

---

### INI Command Processing Pipeline

```mermaid
flowchart LR
  RAW["Raw TCP Data"]:::note
  PARSE["INI Parser"]:::core
  VALID["Command Validation"]:::core
  DISPATCH["Command Dispatcher"]:::core
  EXEC["Service Execution"]:::svc
  RESP["INI Response Builder"]:::core

  RAW --> PARSE
  PARSE --> VALID
  VALID --> DISPATCH
  DISPATCH --> EXEC
  EXEC --> RESP

  classDef core fill:#e8f0ff,stroke:#4a78ff,color:#111;
  classDef svc fill:#eafff1,stroke:#2fb36d,color:#111;
  classDef note fill:#fff7e6,stroke:#e0a800,color:#111;
```

---

### Error Handling & Logging Flow

```mermaid
flowchart TD
  ERR["Exception"]:::fail
  CAT["Error Categorization"]:::core
  LOGF["File Log"]:::svc
  LOGU["UI Log View"]:::svc
  RESP["INI Error Response"]:::core

  ERR --> CAT
  CAT --> LOGF
  CAT --> LOGU
  CAT --> RESP

  classDef core fill:#e8f0ff,stroke:#4a78ff,color:#111;
  classDef svc fill:#eafff1,stroke:#2fb36d,color:#111;
  classDef fail fill:#ffecec,stroke:#d64545,color:#111;
```

All errors are centrally categorized and reported consistently
to logs, UI, and control responses.

---

### Topic Flow

```mermaid
flowchart LR
  PUB["Publish Topic"]:::note
  SUB["Subscribe Topic"]:::note

  EXT["External MQTT Client"]:::ext
  BR["Embedded Broker"]:::svc
  CL["Embedded Client"]:::svc
  EB["External Broker"]:::ext

  EXT --- PUB --- BR
  BR --- SUB --- EXT

  CL --- PUB --- EB
  EB --- SUB --- CL

  classDef ext fill:#f3f3f3,stroke:#999,color:#111;
  classDef svc fill:#eafff1,stroke:#2fb36d,color:#111;
  classDef note fill:#fff7e6,stroke:#e0a800,color:#111;
```

---

### Configuration loading flow

```mermaid
flowchart LR
  FILE["settings.json"]:::note
  LOAD["Settings Loader"]:::core
  APPLY["Apply to Services"]:::core
  UI["UI State"]:::core

  FILE --> LOAD
  LOAD --> APPLY
  APPLY --> UI

  classDef core fill:#e8f0ff,stroke:#4a78ff,color:#111;
  classDef note fill:#fff7e6,stroke:#e0a800,color:#111;
```

---

### Typical Automated Test Scenario

```mermaid
flowchart LR
  STEP1["Start Broker"]:::step
  STEP2["Connect DUT"]:::step
  STEP3["Subscribe Topics"]:::step
  STEP4["Publish Test Data"]:::step
  STEP5["Verify Receive"]:::step
  STEP6["Stop Broker"]:::step

  STEP1 --> STEP2 --> STEP3 --> STEP4 --> STEP5 --> STEP6

  classDef step fill:#e8f0ff,stroke:#4a78ff,color:#111;
```

---

## Troubleshooting

This section lists common failure scenarios and suggested resolutions.

### Broker fails to start

Possible causes:

  - Broker port already in use

  - Invalid or missing PFX certificate

  - Incorrect PFX password

  - TLS protocol mismatch

Recommended actions:

  - Verify the port is not used by another process

  - Validate the PFX file using system tools

  - Confirm TLS version compatibility

---

### Client connection fails

Possible causes:

  - TLS version mismatch (1.2 vs 1.3)

  - Certificate validation mode mismatch

  - Incorrect host or port

  - Connection timeout

Recommended actions:

  - Temporarily enable allowUntrusted=1 to isolate trust issues

  - Verify timeoutMs value

  - Check broker logs for handshake errors

---

### TLS handshake errors

Possible causes:

  - Unsupported TLS protocol

  - Invalid certificate chain

  - Incorrect custom CA configuration

  - Thumbprint mismatch

Notes:

  - Certificate thumbprints are normalized before comparison

  - Whitespace and case differences are ignored

---

### Control server does not respond

Possible causes:

  - Missing blank line at end of packet

  - Incorrect text encoding (must be UTF-8)

  - Firewall blocking the control port

  - Remote connections disabled in settings

---

### Security Notes

The control server is intended for local automation by default.

  - Binding to loopback interface is recommended

  - Enabling remote access requires explicit firewall configuration

  - Raw control packets (RX/TX) are logged to disk

  - Logs may contain sensitive information

  - Disabling “Save passwords” prevents credential persistence

---

### Design Principles

The following principles guide the overall design of the application.

  - The UI acts as an orchestration layer, not a protocol endpoint

  - All automation is performed through the TCP control server

  - Broker and client can operate independently or simultaneously

  - Error handling and logging are centralized

  - State transitions are explicitly tracked and logged

---

### Intended Use Cases

  - MQTT/TLS interoperability testing

  - TLS 1.2 and TLS 1.3 negotiation validation

  - Certificate trust and pinning verification

  - Automated regression testing of MQTT-enabled devices

  - Controlled fault injection and protocol inspection

---

## Download

Prebuilt binaries are available on the GitHub Releases page.

- Windows (net10.0-windows)
- No installer required

See: **Releases → v0.1.0**

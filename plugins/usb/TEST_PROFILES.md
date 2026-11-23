# TEST_PROFILES.md

# USB Validation & Security Testing Console

## Test Profiles Reference Guide

This document describes all Validation Profiles and Security Profiles available within the USB Validation & Security Testing Console.

The objective of this document is to explain:

- What each profile does
- Why the profile exists
- What checks are performed
- How results should be interpreted
- What constitutes PASS or FAIL

---

# Validation Profiles

## Standard USB Validation

This single selector entry groups exactly seven checks: Enumeration Validation,
Descriptor Validation, Descriptor Robustness Test, Endpoint Validation,
CDC Validation, HID Validation and Storage Validation. Their individual
selector entries are removed; the plugin implementations remain reusable.
The checks run sequentially and
produces a live results table plus one combined PDF/CSV report set (no JSON).
The UI requests 30 seconds total revalidation, with fresh seven-check rounds
at 30-second intervals and an end-of-window observation. Slow native calls
can extend the window; cancellation or identity loss can end it early.
Every sample is retained and earlier non-PASS observations cannot be hidden
by later passes. Longer observation does not establish protocol/device-value
correctness or fix descriptor access restrictions. The results window can be
maximized and reopened using **View Results** during the current session.
PDF reports use labelled evidence bullets, a result overview and abbreviations;
raw diagnostic logs are separated from the main findings.
It is not an additional device protocol or a promise to run incompatible
profiles. Endpoint/interface checks require live descriptor evidence; CDC can
also use fresh exact-port Windows `usbser`/CDC-compatible-ID evidence. A COM
port alone does not establish CDC. Absent interfaces are skipped and unavailable evidence is blocked. Metadata-only
mode never substitutes simulation for real I/O.

Stress checks are separate selector entries requiring confirmation, not suite
options or result rows. Active security probes, reconnect, manual serial
console and firmware capture remain separate. All serial configuration and
manual communication use **Serial Console** only; the duplicate suite serial
settings and HEX exchange controls have been removed. The suite never opens a
serial port or sends protocol commands. Serial access and command/response
checks do not appear in the seven-row result table/report. CDC evidence
checks remain part of the suite without proving device command acceptance.

See [One-click applicable device suite](README.md#one-click-applicable-device-suite)
for prerequisites, cancellation and outcome semantics. Descriptor Robustness
Test checks basic metadata/identifier validity, not exhaustive USB robustness.

Validation Profiles confirm that a USB device is correctly recognized, enumerated, and operational.

Validation profiles focus on:

- Device Presence
- USB Descriptors
- USB Class Information
- Enumeration State
- Connection Status

---

# 1. Descriptor Validation

## Purpose

Validates availability of essential USB descriptor information.

## Checks Performed

### Device Name

Verifies that a valid device name is present.

### Vendor ID (VID)

Verifies that a Vendor ID exists.

### Product ID (PID)

Verifies that a Product ID exists.

### USB Class

Verifies that a USB Class is reported.

### Connection State

Verifies that the device is connected.

## PASS Conditions

- All descriptor attributes are present.
- Device reports valid connection state.

## FAIL Conditions

- Missing Device Name
- Missing VID
- Missing PID
- Missing USB Class
- Device disconnected

## Example Output

```text
Device Name Present
VID Found
PID Found
USB Class Detected
Device Connected
```

---

# 2. Enumeration Validation

## Purpose

Verifies successful operating system enumeration.

## Checks Performed

### Device Presence

Validates that the operating system can detect the device.

### VID Availability

Validates Vendor ID availability.

### PID Availability

Validates Product ID availability.

### USB Class Availability

Validates class information availability.

### Connection State

Validates current connection state.

## PASS Conditions

Device successfully enumerated.

## FAIL Conditions

Enumeration incomplete.

## Example Output

```text
Device Found
VID Available
PID Available
USB Class Available
Connection Verified
```

---

# 3. CDC Validation

## Purpose

Validates Communication Device Class devices.

## Typical Devices

- Virtual COM Ports
- USB UART Bridges
- STM32 VCP Devices
- Serial Converters

## Checks Performed

### CDC Detection

Verifies CDC class identification.

### COM Port Assignment

Verifies assignment of communication port.

### VID Validation

Verifies vendor identification.

### PID Validation

Verifies product identification.

### Connection Verification

Verifies current connection.

## PASS Conditions

CDC device enumerates correctly.

## FAIL Conditions

Device is not CDC or missing communication interface.

## Example Output

```text
CDC Device Detected
COM Port Assigned
VID Present
PID Present
Device Connected
```

---

# 4. HID Validation

## Purpose

Validates Human Interface Devices.

## Typical Devices

- USB Keyboard
- USB Mouse
- HID Controllers
- Input Devices

## Checks Performed

### HID Detection

Detects HID class devices.

### Keyboard Detection

Detects keyboard functionality.

### Mouse Detection

Detects mouse functionality.

### VID Verification

Verifies vendor identifier.

### PID Verification

Verifies product identifier.

### Connection Verification

Checks connection status.

## PASS Conditions

Valid HID interface detected.

## FAIL Conditions

Missing HID functionality.

---

# 5. Storage Validation

## Purpose

Validates USB storage devices.

## Typical Devices

- USB Flash Drives
- USB SSDs
- External Storage

## Checks Performed

### Storage Class Detection

Verifies storage functionality.

### VID Verification

Verifies vendor identifier.

### PID Verification

Verifies product identifier.

### Connection Verification

Checks active connection status.

## PASS Conditions

Storage device properly recognized.

## FAIL Conditions

Missing storage characteristics.

---

# 6. Reconnect Validation

## Purpose

Verifies consistency after reconnect events.

## Checks Performed

### Device Name Verification

### VID Verification

### PID Verification

### Connection Verification

### Identity Preservation

Checks whether reconnect causes identity changes.

## PASS Conditions

Device identity remains consistent.

## FAIL Conditions

Identity changes detected.

---

# 7. Stability Validation

## Purpose

Evaluates device stability during monitoring cycles.

## Checks Performed

### Device Presence

### VID Verification

### PID Verification

### Connection Stability

### Disconnect Event Detection

## PASS Conditions

Stable operation through monitoring cycles.

## FAIL Conditions

Unexpected disconnects detected.

## Example Output

```text
Stability Cycle 1/5 Passed
Stability Cycle 2/5 Passed
Stability Cycle 3/5 Passed
Stability Cycle 4/5 Passed
Stability Cycle 5/5 Passed
```

---

# 8. Endpoint Validation

## Purpose

Validates endpoint-related metadata.

## Checks Performed

### Device Validation

### VID Validation

### PID Validation

### USB Class Validation

### Connection Validation

## Current Status

Endpoint discovery currently uses simulated endpoint verification.

## Future Enhancement

- Endpoint Enumeration
- Endpoint Mapping
- Endpoint Security Analysis

---

# Security Profiles

Security Profiles evaluate exposure, risk, robustness and attack surface indicators.

Security Profiles do not identify vulnerabilities directly.

Security Profiles identify:

- Potential Attack Surfaces
- Exposure Levels
- Descriptor Quality
- Communication Risks
- Data Storage Risks

---

# 9. Descriptor Robustness Test

## Purpose

Evaluates descriptor completeness and quality.

## Checks Performed

### Device Name Quality

### VID Format Validation

### PID Format Validation

### USB Class Availability

### Connection Verification

## Generated Metrics

### Descriptor Score

```text
0% - 100%
```

### Risk Rating

```text
LOW
MEDIUM
HIGH
```

## Risk Interpretation

### LOW

Descriptors appear complete.

### MEDIUM

Descriptor information partially available.

### HIGH

Descriptors incomplete or suspicious.

---

# 10. Enumeration Stress Test

## Purpose

Evaluates repeated enumeration stability.

## Checks Performed

### Enumeration Cycle Monitoring

Repeated enumeration verification.

### Success Rate Evaluation

Enumeration success percentage calculation.

### Stability Assessment

Enumeration reliability evaluation.

## Generated Metrics

### Enumeration Success Rate

```text
100%
95%
80%
```

### Risk Rating

```text
LOW
MEDIUM
HIGH
```

## Example Output

```text
Enumeration Cycle 1/10 PASS
Enumeration Cycle 2/10 PASS
Enumeration Cycle 3/10 PASS

Success Rate : 100%
Risk Rating : LOW
```

---

# 11. CDC Security Review

## Purpose

Evaluates communication attack surface exposure.

## Security Focus

Communication devices provide pathways for external system interaction.

## Checks Performed

### CDC Detection

### COM Port Exposure

### External Communication Availability

### VID Verification

### PID Verification

### Connection Verification

## Findings

### Input Channel Available

Device accepts external communication.

### Communication Interface Exposed

Potential communication attack surface.

## Risk Levels

### LOW

No communication interface exposed.

### MEDIUM

Communication interface available.

### HIGH

Bidirectional communication channel available.

---

# 12. HID Attack Surface Review

## Purpose

Evaluates HID-related input attack surface.

## Security Focus

HID devices may generate operating system input events.

## Checks Performed

### HID Detection

### Keyboard Capability Detection

### Mouse Capability Detection

### Generic HID Detection

### Connection Verification

## Findings

### Keyboard Input Capability

Potential input generation capability.

### Mouse Input Capability

Potential cursor control capability.

### HID Interface Exposure

General HID presence.

## Risk Levels

### LOW

Minimal HID exposure.

### MEDIUM

Generic HID device.

### HIGH

Keyboard-style input capability detected.

---

# 13. Storage Exposure Review

## Purpose

Evaluates storage-based exposure risk.

## Security Focus

Storage devices may transfer information into or out of systems.

## Checks Performed

### Storage Detection

### Data Storage Capability

### Read Capability

### Write Capability

### Connection Verification

## Findings

### Removable Media Capability

Storage available.

### Read Access

Device may expose readable content.

### Write Access

Device may accept stored content.

### Data Exfiltration Surface

Potential file transfer capability.

## Risk Levels

### LOW

No storage capability detected.

### MEDIUM

Storage present with limited exposure.

### HIGH

Read and write capable removable storage device.

---

# Risk Rating Guide

## LOW

Minimal exposed attack surface.

Examples

```text
Webcam
Audio Adapter
Basic Peripheral
```

---

## MEDIUM

Moderate interaction capability.

Examples

```text
Generic HID
CDC Interface
Communication Devices
```

---

## HIGH

Significant interaction or storage capability.

Examples

```text
USB Keyboard
CDC Communication Interface
USB Storage Device
```

---

# Understanding PASS vs RISK

PASS does not mean Secure.

PASS means:

```text
The defined validation checks succeeded.
```

Risk Rating indicates:

```text
Potential attack surface exposure.
```

Examples

```text
PASS + LOW RISK

Expected device behavior with minimal exposure.
```

```text
PASS + HIGH RISK

Device operates correctly but exposes significant attack surface.
```

```text
FAIL + HIGH RISK

Device behavior requires investigation.
```

---

# Future Security Profiles

Planned Security Enhancements

- Device Trust Assessment
- USB Identity Analysis
- HID Injection Readiness Assessment
- CDC Traffic Review
- Endpoint Analysis
- Endpoint Security Review
- Descriptor Anomaly Detection
- USB Compliance Assessment
- Endpoint Fuzz Readiness Assessment
- Device Reputation Scoring

---
# Author

Kishor Rankhamb

Engineer II Product Security

USB Validation & Security Testing Console
Development Project

---

# Version

Current Version: v1.0
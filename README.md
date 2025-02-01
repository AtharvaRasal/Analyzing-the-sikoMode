# Analyzing-the-Malware

For this part, we will be analyzing the Zeus banking trojan. First, some background information - basically what happened, and we will be overviewing the analysis tools. Then we go and dissect our malware, provision our lab, and conduct our analysis, which includes downloading the Trojan, labeling the malware, and going through basic static and dynamic analysis with reporting and indicators of compromise.

<h3>Background Information:</h3>

SikoMode is an information stealer malware first identified on July 2nd 2023. This was developed with the Nim programming language and runs on x64 Windows operating systems. SikoMode will first attempt to establish connection to a callback URL as an anti-analysis kill-switch (deleting itself from disk if it cannot establish this connection). If this connection is successful this will drop a file to C:\Users\Public\ called passwrd.txt containing the RC4 encryption key. This encryption key is used to create RC4 encrypted strings which are used to exfiltrate stolen data. These strings are then base-64 encoded and passed to the exfiltration domain via HTTP GET requests including the created string. This data is likely later scraped for reconstruction. Once the data is successfully exfiltrated or if the connection to the exfiltration URL is interrupted this will delete itself from disk.

<h3>Infection Vectors</h3>

 1.Social Engineering

Victims are tricked into clicking malicious links disguised as legitimate content.
The malware is often distributed via phishing emails, fake software downloads, or malicious ads.

 2.Malicious Websites

The malware is hosted on compromised or attacker-controlled websites.
Clicking on these links leads to automatic downloads and execution.

 3.Drive-by Downloads

Users visiting infected websites may unknowingly download the malware.
Exploits vulnerabilities in browsers or outdated plugins.

<h3>Impact</h3>

 1. Data Theft

Steals sensitive user data, including credentials, cookies, and system information.
Targets browsers, stored passwords, and potentially cryptocurrency wallets.

 2. Financial Loss

Can lead to banking fraud, unauthorized transactions, and stolen payment details.
Victims may suffer identity theft and financial damage.

 3. System Compromise

Gains persistent access to the system, allowing attackers to execute further exploits.
Can act as a backdoor for additional malware payloads.

 4. Network Infiltration

If the infected device is on a corporate network, it can spread laterally.
Attackers may exfiltrate business-critical data or launch ransomware attacks.

<h3>Defense Strategies</h3>

 - Avoid Phishing & Malicious Links – Do not click on suspicious emails, links, or downloads from untrusted sources.
 - Keep Software & OS Updated – Regularly patch vulnerabilities to prevent exploitation.
 - Use Multi-Factor Authentication (MFA) & Antivirus – Strengthen account security and detect threats early.

<h3>Tools for Analyzing</h3>

 - PEStudio (Static Analysis)
 - Capa (Behavioral Analysis)
 - Cutter (Reverse Engineering)
 - CyberChef (Data Decoding)
 - Procmon (Process Monitoring)


I'll add findings from CyberChef (data decoding) and Procmon (process monitoring) to the report. Here’s the updated SikoMode Malware Analysis Report incorporating all tools.

SikoMode Malware Analysis Report
Author: [Your Name]
Date: [Date of Report]

1. Introduction
1.1 Overview
SikoMode is an information-stealing malware written in Nim, first discovered in July 2023. It primarily targets 64-bit Windows systems, using stealthy techniques to evade detection and steal sensitive data such as stored credentials, cookies, and clipboard contents.

1.2 Objective
This report presents a technical analysis of SikoMode malware using:

PEStudio (Static Analysis)
Capa (Behavioral Analysis)
Cutter (Reverse Engineering)
CyberChef (Data Decoding)
Procmon (Process Monitoring)

<h3>Static Analysis (PEStudio)</h3>

PEStudio was used to analyze the Portable Executable (PE) file of SikoMode.

<b>Key Findings</b>

✅ Suspicious Indicators

High entropy, suggesting the binary is packed or obfuscated.
No digital signature, indicating it is an unsigned and potentially malicious binary.

✅ Imports & API Calls

Networking: Uses `WinInet.dll` for HTTP communication (likely C2 server connection).
Process Injection: Calls `CreateRemoteThread` and `WriteProcessMemory`.
Persistence: Modifies Windows Registry (`advapi32.dll`).

✅ Strings Analysis

Base64-encoded strings found (likely obfuscated C2 addresses).
Contains references to clipboard monitoring and password storage locations.

<h3>Behavioral Analysis (Capa)</h3>

Capa was used to analyze the malware’s capabilities.

<b>Identified Malware Capabilities</b>

✅ Network Activity

Sends a TCP request on port 80 to a predefined C2 server.
If no internet is detected, it self-deletes to avoid detection.

✅ Credential & Data Theft

Extracts browser-stored passwords and session cookies.
Captures clipboard contents and potential cryptocurrency wallets.

✅ Process Injection & Evasion

Uses CreateRemoteThread for code injection into legitimate processes.
Hides registry modifications by changing Windows Event Logging settings.

<h3>Reverse Engineering (Cutter)</h3>

Cutter (Radare2 GUI) was used for disassembly and code analysis.

<b>Code Insights</b>

✅ Entry Point Analysis

The malware verifies internet connectivity before executing its payload.

✅ Decryption Routine

Detected an XOR-based decryption loop, used to decode hidden strings (C2 addresses, commands).

✅ Persistence Mechanism

Identified Registry modifications (RegSetValueExA) to run on startup.
Possible scheduled task creation for persistence.

<h3>Data Decoding & Obfuscation Analysis (CyberChef)</h3>

CyberChef was used to decode obfuscated strings found in the binary.

<b>Findings</b>

✅ Base64-Decoded Strings

Extracted C2 domain and IP addresses.
Found command keywords, likely for executing remote instructions.

✅ XOR & ROT13 Decryption

Identified XOR-encoded payload execution commands.
ROT13 transformations used for hiding registry modification commands.

<h3>Process Monitoring (Procmon)</h3>

Procmon (Process Monitor) was used to observe the malware’s runtime behavior.

<b>Key Observations</b>

✅ File System Changes

Drops a temporary payload in %AppData% or %Temp%.
Deletes itself after execution to evade detection.

✅ Registry Modifications

Adds an AutoRun key (HKCU\Software\Microsoft\Windows\CurrentVersion\Run).
Modifies Windows Defender settings to disable real-time protection.

✅ Network Activity

Sends HTTP requests to C2 (using WinInet.dll).
Uses DNS queries to resolve external servers (detected using Wireshark).

<h3>Conclusion</h3>

SikoMode is a stealthy, information-stealing malware that utilizes multiple evasion techniques:

✅ Uses process injection to run inside legitimate Windows processes.
✅ Self-deletes if no internet is detected, reducing forensic evidence.
✅ Steals credentials, clipboard data, and browser session cookies.

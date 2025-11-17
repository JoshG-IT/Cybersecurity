<p align="center">
  <img src="https://raw.githubusercontent.com/JoshG-IT/Cybersecurity/e860def66560739a0b007f98125776d8f1208720/Assets/SVG/CTH1.svg" width="800" alt="Threat Hunt Report Title"/>
</p>

# Support Session Misdirection

**Hunter:** Josh G.

**Environment:** Log Analytics Workspace 

**Timeframe Analyzed:** 2025-10-01 - 2025-10-15 UTC  

---

<p align="center">
  <img src="https://github.com/JoshG-IT/Cybersecurity/blob/06a052cc790c1758a4cae4b54fc9623a832b9790/Assets/SVG/CTH2.svg" width="800" alt="Threat Hunt Report Title"/>
</p>

A workstation used by an intern showed signs of suspicious activity after what appeared to be a remote “support” session. The attacker ran a fake support tool that collected information about the system, checked who was logged in, reviewed copied text from the clipboard, and tested internet connections. It later saved all findings into a zip file, set up ways to automatically run again, and left behind a fake support log file to cover its tracks.  

---

<p align="center">
  <img src="https://github.com/JoshG-IT/Cybersecurity/blob/d20affd64aabbcb88eb66da26605e4117436099a/Assets/SVG/CTH3.svg" width="800" alt="Threat Hunt Report Title"/>
</p>

The host **gab-intern-vm** executed a PowerShell script named **SupportTool.ps1** from the Downloads folder using the `-ExecutionPolicy Bypass` flag, allowing it to run without restrictions. The script performed local reconnaissance, including clipboard access, session discovery, and drive enumeration. PowerShell was executed under **RuntimeBroker.exe**, a parent process.  

After enumeration, the attacker archived data into **C:\Users\Public\ReconArtifacts.zip**, verified outbound connectivity through **www.msftconnecttest.com**, and communicated with **100.29.147.161**. Persistence was achieved via a scheduled task (**SupportToolUpdater**) and a registry autorun key (**RemoteAssistUpdater**). A fake “Support Chat” log (**SupportChat_log.lnk**) was planted afterwards.  

---

<p align="center">
  <img src="https://github.com/JoshG-IT/Cybersecurity/blob/06a052cc790c1758a4cae4b54fc9623a832b9790/Assets/SVG/CTH7.svg" width="800" alt="Threat Hunt Report Title"/>
</p>

---

## Flag 0 - Starting Point
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Identify which host initiated suspicious activity from the Downloads folder. |
| **Technical Objective** | Detect endpoints executing files containing support/help/tool keywords. |
| **Expected Query** | `DeviceProcessEvents \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("Downloads","download","support","help","tool","desk") \| summarize executions=count() by DeviceName \| order by executions desc` |
| **Actual Query Used** | `DeviceProcessEvents \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where ProcessCommandLine has_any ("Downloads","support","help","desk","tool")` |
| **Answer** | gab-intern-vm |
| **Non-Technical Explanation** | The compromised virtual machine was identified by its repeated execution of suspicious files from Downloads. |
| **Technical Explanation** | Multiple hits on gab-intern-vm for scripts in Downloads containing help/support keywords confirm it as the infected endpoint. |
| **Screenshot** | <img width="574" height="622" alt="image" src="https://github.com/user-attachments/assets/79e52d81-1b1e-410b-897f-3f55f3220fd7" />|

---

### Flag 1 - Initial Execution Detection
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Identify what first triggered the suspicious session. |
| **Technical Objective** | Detect earliest abnormal PowerShell execution from Downloads. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("Downloads") \| project Timestamp, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where ProcessCommandLine has_any ("Downloads","download","ExecutionPolicy") \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15))` |
| **Answer** | `-ExecutionPolicy` |
| **Non-Technical Explanation** | A fake support tool was manually run, starting the attack. |
| **Technical Explanation** | PowerShell executed `SupportTool.ps1` with `-ExecutionPolicy Bypass`, allowing unrestricted script execution. |
| **Screenshot** | <img width="934" height="629" alt="image" src="https://github.com/user-attachments/assets/010af477-d8e1-4e06-8e1d-dbfe60ba7030" />|

---

### Flag 2 - Defense Disabling
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Find if someone faked security alerts to look legitimate. |
| **Technical Objective** | Detect staged Defender-related artifacts. |
| **Expected Query** | `DeviceFileEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06) .. datetime(2025-10-11)) \| extend lowerName = tolower(tostring(FileName)) \| where lowerName endswith ".lnk" or lowerName endswith ".txt" \| where ActionType in ("FileCreated","FileOpened","FileModified","FileAccessed") \| summarize hits = dcount(FileName) by FolderPath, InitiatingProcessFileName \| order by hits desc` |
| **Actual Query Used** | `DeviceFileEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where ActionType in ("FileCreated","FileOpened","FileModified","FileAccessed") \| summarize hits = dcount(FileName) by FolderPath, InitiatingProcessFileName \| order by hits desc` |
| **Answer** | `DefenderTamperArtifact.lnk` |
| **Non-Technical Explanation** | The attacker created fake antivirus files to appear as normal logs. |
| **Technical Explanation** | Staged artifacts were planted to simulate Defender tampering without real modification. |
| **Screenshot** | <img width="1036" height="763" alt="image" src="https://github.com/user-attachments/assets/1ed73e0a-a0e9-49e0-be3b-bd9a1f56bf7c" /> |

---

### Flag 3 - Quick Data Probe
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Check if sensitive copied text was viewed. |
| **Technical Objective** | Identify STA PowerShell clipboard access. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("Get-Clipboard") \| project Timestamp, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp asc` |
| **Answer** | `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard \| Out-Null } catch { }"` |
| **Non-Technical Explanation** | The attacker tried to read text copied to the clipboard. |
| **Technical Explanation** | PowerShell executed with STA mode to silently capture clipboard contents. |
| **Screenshot** | <img width="1016" height="769" alt="image" src="https://github.com/user-attachments/assets/d18de71a-f8aa-4997-ba33-87cad488d89c" /> |

---

### Flag 4 - Host Context Recon
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Determine when the system was last explored. |
| **Technical Objective** | Detect recon commands like `qwinsta` or `query session`. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("qwinsta","query session") \| project Timestamp, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| project Timestamp, FileName, ProcessCommandLine, ProcessId, ProcessUniqueId, InitiatingProcessFileName \| order by Timestamp asc` |
| **Answer** | `2025-10-09T12:51:44.3425653Z` |
| **Non-Technical Explanation** | The attacker viewed logged-in users and sessions. |
| **Technical Explanation** | Reconnaissance confirmed through timestamped session query commands. |
| **Screenshot** | <img width="931" height="755" alt="image" src="https://github.com/user-attachments/assets/1dbfd9b4-923e-4ff7-ae35-e8a22c34f2ad" /> |

---

### Flag 5 - Storage Surface Mapping
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | See if they explored available drives. |
| **Technical Objective** | Detect disk enumeration and free-space queries. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("logicaldisk")` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") \| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId, InitiatingProcessId \| order by Timestamp asc` |
| **Answer** | `"cmd.exe" /c wmic logicaldisk get name,freespace,size"` |
| **Non-Technical Explanation** | The attacker checked local drives and available storage. |
| **Technical Explanation** | WMIC command used to assess free space and drive mapping. |
| **Screenshot** | <img width="1012" height="761" alt="image" src="https://github.com/user-attachments/assets/0daa0590-43b6-4a6c-8a68-d58f31311a85" /> |

---

### Flag 6 - Connectivity & Name Resolution Check
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Find how they tested the internet connection. |
| **Technical Objective** | Detect egress or DNS resolution attempts. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("ping","nslookup") \| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") \| where ProcessCommandLine has_any ("ping","nslookup")` |
| **Answer** | `RuntimeBroker.exe` |
| **Non-Technical Explanation** | The script verified network connectivity. |
| **Technical Explanation** | PowerShell spawned by RuntimeBroker.exe, suggesting abnormal parent process. |
| **Screenshot** | <img width="780" height="755" alt="image" src="https://github.com/user-attachments/assets/64ed87d0-867f-4175-9ed1-743487fb35e2" /> |

---

### Flag 7 - Interactive Session Discovery
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Identify attempts to list who’s logged in. |
| **Technical Objective** | Find session enumeration commands and the initiating process unique id. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("quser","query session","qwinsta") \| project Timestamp, ProcessUniqueId, InitiatingProcessUniqueId, ProcessCommandLine \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") \| where ProcessCommandLine has_any ("query session")` |
| **Answer** | `2533274790397065` |
| **Non-Technical Explanation** | The attacker checked which users were active. |
| **Technical Explanation** | Session enumeration events show the initiating process unique id that links this action to the attacker chain. |
| **Screenshot** | <img width="697" height="766" alt="image" src="https://github.com/user-attachments/assets/258a5aeb-60fa-4476-a88d-c088a7256f04" /> |

---

### Flag 8 - Runtime Application Inventory
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Determine if running applications were listed. |
| **Technical Objective** | Identify runtime process/service enumeration behavior. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("tasklist") \| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")` |
| **Answer** | `tasklist.exe` |
| **Non-Technical Explanation** | The attacker enumerated running programs to see what was active. |
| **Technical Explanation** | Tasklist was executed (often with /v) by the attacker chain to capture a full view of running processes and owners. |
| **Screenshot** | <img width="962" height="769" alt="image" src="https://github.com/user-attachments/assets/f755c7d6-9e89-4d12-afca-9dcea64055be" /> |

---

### Flag 9 - Privilege Surface Check
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | See if they checked their permission level. |
| **Technical Objective** | Identify the earliest privilege enumeration event. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp asc \| where ProcessCommandLine has_any ("whoami","/groups","/all","net user","net localgroup")` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")` |
| **Answer** | `2025-10-09T12:52:14.3135459Z` |
| **Non-Technical Explanation** | The attacker verified their access level right after recon. |
| **Technical Explanation** | The earliest whoami /groups execution timestamp ties privilege mapping to the malicious PowerShell/cmd chain. |
| **Screenshot** | <img width="695" height="727" alt="image" src="https://github.com/user-attachments/assets/4ac90690-8494-470f-a616-1fcde220c0c7" /> |

---

### Flag 10 - Proof-of-Access & Egress Validation
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Determine if they tested internet reachability. |
| **Technical Objective** | Identify the first outbound destination contacted during the attacker window. |
| **Expected Query** | `DeviceNetworkEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceNetworkEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")` |
| **Answer** | `www.msftconnecttest.com` |
| **Non-Technical Explanation** | A connectivity probe to a Microsoft test domain confirmed outbound reachability. |
| **Technical Explanation** | The attacker used a lightweight HTTP call (msftconnecttest) as a proof-of-egress before attempting larger transfers. |
| **Screenshot** | <img width="1177" height="759" alt="image" src="https://github.com/user-attachments/assets/6aefe8ef-7e97-499b-a2a1-a990f9c4935e" />|

---

### Flag 11 - Bundling / Staging Artifacts
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Check if gathered data was saved in one place. |
| **Technical Objective** | Detect .zip archive creation used for bundling artifacts. |
| **Expected Query** | `DeviceFileEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| extend lowerName=tostring(tolower(FileName)) \| where lowerName endswith ".zip" or lowerName has "*artifacts" \| project Timestamp, FileName, FolderPath, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceFileEvents \| where DeviceName == "gab-intern-vm" \| where FileName endswith ".zip" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")` |
| **Answer** | `C:\Users\Public\ReconArtifacts.zip` |
| **Non-Technical Explanation** | The attacker consolidated collected items into a single archive. |
| **Technical Explanation** | PowerShell created a ZIP in a world-readable location (C:\Users\Public) to stage data for exfiltration. |
| **Screenshot** | <img width="1192" height="748" alt="image" src="https://github.com/user-attachments/assets/35cf33c8-221e-4b45-9446-78c610ed846c" /> |

---

### Flag 12 - Outbound Transfer Attempt (Simulated)
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | See if the tool tried to send files out. |
| **Technical Objective** | Detect suspicious outbound connections initiated by attacker-controlled processes. |
| **Expected Query** | `DeviceNetworkEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| project Timestamp, RemoteIP, RemoteUrl, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceNetworkEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")` |
| **Answer** | `100.29.147.161` |
| **Non-Technical Explanation** | The host attempted an outbound connection to an unusual external IP (simulated exfil target). |
| **Technical Explanation** | The last suspicious outbound IP observed from attacker processes was 100.29.147.161 (httpbin/http upload test behavior). |
| **Screenshot** | <img width="950" height="712" alt="image" src="https://github.com/user-attachments/assets/b7f9f3ec-56a0-4aca-ad24-b585eaf10a40" /> |

---

### Flag 13 - Scheduled Re-Execution Persistence
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Find if the tool set itself to re-launch automatically. |
| **Technical Objective** | Detect new scheduled task creation linked to the attacker. |
| **Expected Query** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06)..datetime(2025-10-11)) \| where ProcessCommandLine has_any ("schtasks") \| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceProcessEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15)) \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") \| where ProcessCommandLine has_any ("schtasks")` |
| **Answer** | `SupportToolUpdater` |
| **Non-Technical Explanation** | A scheduled task named SupportToolUpdater was created to persist the tool. |
| **Technical Explanation** | schtasks /Create with /TN SupportToolUpdater registered a logon-triggered PowerShell action to re-run the malicious script. |
| **Screenshot** | <img width="1564" height="560" alt="image" src="https://github.com/user-attachments/assets/9eb6a85e-29a7-4089-bef3-472a29f40328" /> |

---

### Flag 14 - Autorun Fallback Persistence
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Check for backup startup methods used to maintain persistence. |
| **Technical Objective** | Hunt for user-scope autorun registry modifications (HKCU\...\Run, RunOnce) or startup-folder entries that reference previously observed commands or binaries. |
| **Expected Query** | `DeviceRegistryEvents \| where Hyperventilate  \| because I spent an hour searching before realizing the damn answer was literally in the question 🤦‍♂️` |
| **Actual Query Used** | `DeviceRegistryEvents \| where Timestamp between (datetime(2025-10-01)..datetime(2025-10-15))` |
| **Answer** | `RemoteAssistUpdater` |
| **Why the registry hit is not observable here** | The Log Analytics workspace / dataset available for this challenge doesn't include DeviceRegistryEvents table
| **Non-Technical Explanation** | We couldn't retrieve a registry record in the available data. I'm assuming the SupportToolUpdater is another misdirection. |
| **Technical Explanation** | Process evidence shows the attacker created scheduled-task persistence (SupportToolUpdater) via schtasks.exe. |
| **Screenshot** | <img width="780" height="484" alt="image" src="https://github.com/user-attachments/assets/4d935fb9-4203-4e9c-ada6-a7cc6f049743" /> |

---

### Flag 15 - Planted Narrative / Cover Artifact
| **Attribute** | **Details** |
|----------------|-------------|
| **Non-Technical Objective** | Detect fake logs or cover stories. |
| **Technical Objective** | Identify planted user-facing files created after suspicious operations. |
| **Expected Query** | `DeviceFileEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-06) .. datetime(2025-10-11)) \| extend lowerName = tolower(tostring(FileName)), lowerPath = tolower(tostring(FolderPath)) \| where ActionType in ("FileCreated","FileModified","FileOpened","FileAccessed") \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe","explorer.exe") \| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName \| order by Timestamp asc` |
| **Actual Query Used** | `DeviceFileEvents \| where DeviceName == "gab-intern-vm" \| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15)) \| where ActionType in ("FileCreated","FileModified","FileOpened","FileAccessed") \| where InitiatingProcessFileName in ("powershell.exe","cmd.exe","explorer.exe") ` |
| **Answer** | `SupportChat_log.lnk` |
| **Non-Technical Explanation** | A helpdesk-style log file was dropped to provide a benign explanation for the activity. |
| **Technical Explanation** | The file was created/opened in the same session as the attacker actions, indicating a planted narrative rather than a legitimate support transcript. |
| **Screenshot** | <img width="1403" height="764" alt="image" src="https://github.com/user-attachments/assets/4264ec03-9d0d-41d0-b397-ac0753b749cf" /> |


---

<p align="center">
  <img src="https://github.com/JoshG-IT/Cybersecurity/blob/af6671003cf62e8432de679f8f34efb8b78ce3fd/Assets/SVG/CTH8.svg" width="800" alt="Threat Hunt Report Title"/>
</p>

| Action | Description |
|--------|-------------|
| **Delete Malicious Files** | Remove `SupportTool.ps1`, `DefenderTamperArtifact.*`, `ReconArtifacts.zip`, and `SupportChat_log.*`. |
| **Disable Persistence** | Delete scheduled task `SupportToolUpdater` and registry key `RemoteAssistUpdater`. |
| **Restrict PowerShell** | Enforce signed script execution and apply through GPO. |
| **Enhance Monitoring** | Alert of `.zip` creation in public directories and detect PowerShell scripts that run. |
| **User Education** | Remind users never to run downloaded tools without IT approval. |

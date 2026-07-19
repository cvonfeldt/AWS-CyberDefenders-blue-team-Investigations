# Overview: 

### A prominent U.S.-based organization recently received an official notification from AWS alerting them to a potential security breach: one of their AWS access keys appears to have been compromised. Coincidentally, a subsequent internal security alert indicated that CloudTrail logging had been unexpectedly disabled.

![Overview](screenshots/OV.png)

<br>

### Methodology: 

**We are tasked with using jq to thoroughly investigate this series of events, and figure out the timeline of these events.**

---

<br>

### Attack Chain: 

---

<br> 

## Indicators of Compromise:

| IOC Type                  | Value               |
| -------------------------- | -------------------- |

---

<br>

## MITRE ATT&CK Mapping:

| ATT&CK ID | Technique                                                | Evidence                                        |
| --------- | -------------------------------------------------------- | ----------------------------------------------- |

---

<br>

## Investigation:

### 1. To properly track the activities done by the attacker in the environment, you will need to determine the source of the attack. What is the attacker's IP address?

**Answer:**

---


### 2. A timeline for the incident will help identify the gaps in your investigation. When did the attacker interact with the server for the first time?

**Answer:**

---

### 3. To ensure the environment is safe after the recent breach, identifying the attacker's entry point is essential. What is the exact file path from which the attacker retrieved the compromised user access key?


**Answer:**

---

### 4. In a cloud environment, determining the user context can help assess the potential extent of damage based on the permissions and resources accessible to that user. What is the 'Type' of the user who disabled CloudTrail?

**Answer:**

---

### 5. From the previous question, you determined the attacker's access type; now, you need to figure out what resources the attacker has access to. What is the name of the role the attacker takes advantage of to escalate his privilege in the environment?

**Answer:**

---

### 6. In AWS, to enhance security, users are granted temporary access to specific resources when they assume a role. This action results in the creation of a session, characterized by a unique name and credentials. To trace the attacker's TTPs, can you identify the name of the session they initiated?

**Answer:**

---

### 7. To effectively mitigate risks, it's crucial to determine whether the attacker attempted to establish persistence for ongoing access. Can you identify the name of the user the attacker created to maintain a foothold on the machine?

**Answer:**

---

### 8. The attacker leveraged several techniques to access the account they created. What is the event name associated with their initial method?

**Answer:**


---

### 9. What is the name of the group the attacker added the newly created user to?

**Answer:**

---

### 10. Sophisticated threat actors often attempt to conceal their TTPs. Can you provide the exact time CloudTrail logging was disabled?

**Answer:**

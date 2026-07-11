# Overview: 

**On January 23, 2026, Maromalix's finance department received an alarming call from TechCorp Industries, a long-standing client. TechCorp's accounts payable team reported they had processed a wire transfer to what they believed was Maromalix's bank account after receiving an invoice for services rendered. However, Maromalix had not issued any such invoice to TechCorp.**

**During the week prior to the incident, Maromalix onboarded a new cloud administrator. During this transition period, several IAM permission adjustments were made as users reported access issues with various services. Some of these changes may have resulted in overly permissive policies—activity related to these legitimate administrative actions may appear in the logs.**

![Overview](screenshots/OV.png)

<br>

### Methodology: 

**The primary investigation tool will be AWS CloudWatch Logs Insights—use it to query CloudTrail and Lambda execution logs, reconstruct the attack timeline, and identify indicators of compromise.**

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

# Investigation:

## 1. Reconaissance

### 1.1) During the initial threat hunting phase, analysis of CloudTrail logs revealed API calls from multiple source IP addresses. One IP address stood out as highly suspicious due to its association with multiple identities and offensive security tooling. What is this attacker's IP address?

**Answer:**

### 1.2) The attacker's first action was to probe for publicly accessible resources. What is the full name of the S3 bucket they discovered?

**Answer:**

---

<br>

## 2. Initial Access

### 2.1) The attacker used a tool designed to scan repositories and file systems for exposed secrets, then automatically validate any discovered credentials. What is the name of this tool?

**Answer:**

### 2.2) The credentials discovered by the attacker belonged to a service account. What is the name of this initially compromised user?

**Answer:**

---

<br>

## 3. Discovery #1

### 3.1) To systematically enumerate the AWS environment and discover potential privilege escalation paths, the attacker used an open-source cloud exploitation framework. Provide the name and version of this tool as recorded in the logs.

**Answer:**

---

<br>

## 4. Privilege Escalation

### 4.1) The attacker discovered an overly permissive trust policy and escalated their privileges. What is the name of the first role the attacker successfully assumed?

**Answer:**

### 4.2) When assuming the new role, the attacker specified a custom session name to identify their session. What was this session name?

**Answer:**

---

<br>

## 5. Discovery #2

### 5.1) With elevated privileges, the attacker enumerated several AWS services looking for sensitive data. Which AWS service did they successfully query to discover stored credentials and secrets?

**Answer:**

---

<br>

## 6. Credential Access #1

### 6.1) After discovering the secrets inventory, the attacker began exfiltrating credentials. What is the ID of the first secret the attacker retrieved?

**Answer:**

### 6.2) What is the MITRE ATT&CK technique ID that corresponds to this credential exfiltration behavior?

**Answer:**

---

<br>

## 7. Lateral Movement

### 7.1) Using credentials obtained from the exfiltrated secrets, the attacker pivoted to a different IAM role. What is the full name of this role?

**Answer:**

---

<br>

## 8. Credential Access #2

### 8.1) The attacker used their new role to remotely execute commands on an EC2 instance and steal its IAM credentials via the Instance Metadata Service (IMDS). Provide the API call used to execute commands and the instance ID of the compromised machine, separated by a comma.

**Answer:**

---

<br>

## 9. Discovery #3

### 9.1) With EC2 instance credentials, the attacker enumerated Lambda functions by downloading their configurations and code. What is the name of the first Lambda function the attacker retrieved?

**Answer:**

### 9.2) After examining multiple functions, the attacker identified one suitable for their attack. What is the name of the Lambda function he used to send fraudulent emails?

**Answer:**

---

<br>

## 10. Impact

### 10.1) The attacker sent fraudulent emails to two recipients. Provide both email addresses separated by a comma, with the internal recipient first.

**Answer:**

### 10.2) The fraudulent invoice included attacker-controlled contact email addresses. What are the two domains used for these contact addresses? (Provide both domains separated by a comma, in alphabetical order)

**Answer:**

### 10.3) The attacker's ultimate goal was to deceive the victim into transferring funds via a fraudulent invoice. What is the MITRE ATT&CK technique ID that corresponds to this impact?

**Answer:**

### 10.4) Based on the tools, TTPs, and infrastructure patterns observed in this investigation, this incident matches a known threat campaign. What is the name of this campaign?

**Answer:**

---

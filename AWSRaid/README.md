# Overview: 

## Your organization utilizes AWS to host critical data and applications. An incident has been reported that involves unauthorized access to data and potential exfiltration. The security team has detected unusual activities and needs to investigate the incident to determine the scope of the attack.

<br>

### Methodology: 

**The primary investigation tool will be Splunk to parse CloudTrail logs and reconstruct the attacker's kill chain**

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

### 1. Knowing which user account was compromised is essential for understanding the attacker's initial entry point into the environment. What is the username of the compromised user?

For this one I want to just make a simple query: 

index="aws_cloudtrail"
| sort by eventTime asc

To see what the log structure and fields look like: 

![Q1](screenshots/1.000.png)

It seems like the eventName field would help us narrow down which account was compromised and the method: 

![Q1](screenshots/1.00.png)

check users associated with logins and it was luke 

![Q1](screenshots/1.01.png)

indicative of brute force (9 failed logins followed by success starting at 9:53:27.000 AM w 2-5 secs between each)

**Answer: helpdesk.luke**

---


### 2. We must investigate the events following the initial compromise to understand the attacker's motives. What is the timestamp for the first access to an S3 object by the attacker?

checked for eventnames associated to helpdesk.luke:

![Q2](screenshots/2.png)

found bucketName field, found only getObject could be the accessing of the S3 bucket: 

![Q2](screenshots/2.1.png)

sorted in asc order and opened first getObject log: 

![Q2](screenshots/2.2.png)

timestamp is 2023-11-02T09:55:53Z

**Answer: 2023-11-02 09:55**

---

### 3. Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket?

Searching the same query but adding a "DWG" filter to it, we get:

![Q3](screenshots/3.0.png)

Here we can see that the file "Product2_CAD_Designs.dwg" was from the bucket "product-designs-repository31183937"
**Answer: product-designs-repository31183937**

---

### 4. We've identified changes to a bucket's configuration that allowed public access, a significant security concern. What is the name of this particular S3 bucket?
We can see in #2 a call called PutBucketPublicAccessBlock, so let's analyze it:


**Answer:**

---

### 5. Creating a new user account is a common tactic attackers use to establish persistence in a compromised environment. What is the username of the account created by the attacker?

**Answer:**

---

### 6. Following account creation, the attacker added the account to a specific group. What is the name of the group to which the account was added?

**Answer:**

---

<br> 

## Completed:

![done](screenshots/complete.png)

# Overview: 

### On October 15, 2024, a security breach occurred involving a web application named "Visa Checker," which was hosted on an AWS EC2 instance. The attacker exploited a Server-Side Request Forgery (SSRF) vulnerability within the application, enabling them to steal IAM role credentials. With these compromised credentials, the attacker gained unauthorized access to sensitive information stored in Amazon S3 bucket. This S3 bucket contained data on approximately 20 million tourists.

**The attacker leveraged the stolen credentials to perform various unauthorized actions within the AWS environment, including data exfiltration. To evade detection, the attacker routed their traffic through multiple Tor exit nodes, using anonymized IP addresses to obscure their true location, making it difficult to trace the source of the attack.**

![Overview](screenshots/OV.png)

<br>

### Methodology: 

**We will use a PCAP file and CloudWatch Logs from the incident for analysis. The goal is to identify the attacker's actions, determine the compromised resources, and assess the overall scope and impact of the breach.**

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

### 1. The attacker tested the SSRF vulnerability by accessing an external website. What URL was used to conduct this test?
For this we should analyze http packets in wireshark: 

![Q1](screenshots/Q1.png)

We see lots of get requests from visa-status app to http://visa-checker-atlantes.com, but this is the legit GET request that the app is intended to make. We see a request to google however from IP:45.84.107.198. 

**Answer: http://www.google.com**

---


### 2. The attacker exploited the vulnerable website to send requests, ultimately obtaining the IAM role credentials. What is the exact URI used in the request made by the webserver to acquire these credentials?

There are lots of server-side requests to 169.254.169.254:

![Q2](screenshots/Q2.png)

But one in particular where the full URI is indicative of stealing server-side credentials.  

**Answer: http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-S3-Visa**

---

### 3. The attacker executed an AWS CLI command, similar to whoami in traditional systems, to retrieve information about the IAM user or role associated with the operation. When exactly did he execute that command?


**Answer:**

---

### 4. During the investigation of the network traffic, we observed that the attacker attempted to retrieve the instance ID and subsequently tried to terminate or shut down the instance. What was the error code returned?

**Answer:**

---

### 5. The attacker made an attempt to create a new user but lacked the necessary permissions. What was the username the attacker tried to create?

**Answer:**

---

### 6. Which version of the AWS CLI did the attacker use?

**Answer:**

---

### 7. After listing the available S3 buckets, the attacker proceeded to list the contents of one of them, Which bucket did the attacker list its contents?

**Answer:**

---

### 8. The attacker subsequently began downloading data from the bucket. What was the total amount of data stolen, measured in bytes?

**Answer:**


---

### 9. After stealing the data, the attacker began deleting the contents of the bucket. What IP address was used during these deletion activities?

**Answer:**

---

### 10. The attacker executed a deletion operation on the bucket, removing all of its contents. Every request in AWS is linked to a unique identifier for tracking purposes. What was the request ID associated with the bucket's deletion event?

**Answer:**

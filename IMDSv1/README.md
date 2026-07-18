# Overview: 

<br>

### Methodology: 

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

**Answer:**

---


### 2. The attacker exploited the vulnerable website to send requests, ultimately obtaining the IAM role credentials. What is the exact URI used in the request made by the webserver to acquire these credentials?

**Answer:**

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

# Overview: 

**Between 20 and 25 February 2025, Compliant Secure Store recently launched its new website, but security misconfigurations left critical gaps. Soon after the launch, an attacker initiated widespread scanning and discovered an upload feature that processed XML data without proper validation. By crafting a specially designed payload, the attacker manipulated the system’s input handling, triggering unintended data exposure.**

**Using the extracted information from this vulnerability, the attacker authenticated into the system and navigated internal resources. During the exploration, misconfigured storage buckets were discovered, and sensitive records were exfiltrated before the security team could intervene.**

(screenshots/Overview.png)

<br>

### Methodology: 

**Using the AWS console to analyze AWS GuardDuty, CloudTrail, S3, and CloudWatch logs to identify attacker actions, exploited misconfigurations, and reconstruct an AWS cloud security incident. Our mission is to analyze the attack flow, identify exploited weaknesses, and implement the necessary security controls to prevent future incidents.**

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

### 1. During the initial scanning, the attacker interacted with the web application from an external IP address. What is the origin IP tied to the attacker, as observed in the AWS logs?

So we know init_start/start/end/report/etc. data doesn't have any info about IPs, so we need to look for custom logging within the timeframe of the attack (feb 20th to feb 25th). Looking through all lambda logs, we see the first of what looks like a custom log:
(screenshots/1.png)

We indeed see an IP address in this custom log, so we know that "Received events:" is what we need to query for in our logs, and we can go from there. Searching the query: 

```sql
SOURCE "arn:aws:logs:us-east-1:149536493376:log-group:/aws/lambda/FileUpload" START=2025-02-20T01:00:00.000Z END=2025-02-25T23:59:59.000Z |
fields @timestamp, @requestId
| filter @message like /Received event/
| sort @timestamp asc
```

There are pretty evenly spaced out logs, then there are a burst of ~20 logs within a span of 15 minutes, which is very characteristic of the attacker scan we are looking for. Investigating these logs, we see very suspicious activity uploading files called random_file.jpg, user_database_2693.db, and many files with large volumes of base64 encoded file data. 

**For this question, we find that they all have a sourceIP of 41.46.53.241.**

**Answer: 41.46.53.241**

---

### 2. A code review uncovered a function that lacked proper input validation, enabling arbitrary file processing. Which function’s misconfiguration directly enabled the initial exploit?

For this we want to look again at the logs within the initial scan. We see that they all have the lambda function attribute of "FileUpload"

**Answer: FileUpload**

---

### 3. The attacker uploaded a file masquerading as a benign document but containing an embedded malicious payload. What’s the filename of the SVG payload disguised as a financial record?

To search specifically for logs with .svg files, we switch the query to:

```sql
fields @timestamp, @requestId, @message
| filter @message like /\.svg/
| sort @timestamp asc
```

The results show only 1 log that occurred after the initial scan:

(screenshots/2.png)

Here we can see that the file uploaded is "financial_statement_2143.svg"

**Answer: financial_statement_2143.svg**

---

### 4. During analysis of the CloudWatch Logs, the attacker’s external IP address was observed invoking an API to upload files to an S3 bucket. What is the exact URL path used for this upload operation, as seen in the logs?

For this one, quick search tells us that the exact AWS API gateway structure is "https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/{resource-path}", and we see in one of the many file uploads from the attacker:

(screenshots/3.png)

That the domain is "upilqcjrp5.execute-api.us-east-1.amazonaws.com", the stage is "prod", and the resourcePath is "/dev/upload" - for confirmation it says the path is those combined: "/prod/dev/upload." Putting it all together we get: "https://upilqcjrp5.execute-api.us-east-1.amazonaws.com/prod/dev/upload". This is consistent with all of the file uploads from the attacker, so we can deduce it's the upload(s) to the S3 bucket.

**Answer: https://upilqcjrp5.execute-api.us-east-1.amazonaws.com/prod/dev/upload**

---

### 5. Which IAM role with excessive permissions was abused during the attack and used to query sensitive S3 buckets?

For this we can go to the lambda configurations to check IAM roles:

(screenshots/4.png)

We can see the only role associated with the fileupload function is "LambdaParser." This instance provided by cyberdefenders doesn't allow to investigate deeper the IAM role, but it is common to have file parser custom functions in lambda to process/extract S3 files.

**Answer: LambdaParser**

---

### 6. What is the MITRE ATT&CK technique related to the attacker’s use of valid cloud credentials to log into the system?

The specific MITRE ATT&CK technique for using valid cloud credentials to log into a system is Valid Accounts (Technique T1078), specifically the sub-technique Cloud Accounts (T1078.004)

**Answer: T1078.004**

---

### 7. A server error inadvertently disclosed a temporary AWS access key in the older S3 bucket logs. What is the AccessKeyId value that was leaked?

For this one I looked all over, trying to analyze ERROR logs, looking at cloudtrail events (ones I have access to - only last 90 days), searching specifically for

fields @timestamp, @message
| filter @message like /accessKeyId/ or @message like /AccessKeyId/ or @message like /ASIA/
| sort @timestamp asc

And nothing. I had to look up the answer (*key redacted due to github secret sharing policy*), and even after finding the answer online and specifically searching for it in the logs, I couldn't find it - and it wouldn't be any part of the Base64 encoding we saw because it was leaked by AWS. I'm thinking that when this lab was created, they gave the instance more privileges but have since taken them away. The answer I found online found the Access Key by going to GuardDuty, which I don't have access to. 

Even in the overview of the lab it states: **Note: To solve this lab, you will need to use CloudWatch Log Insights to analyze the logs and identify the attack patterns. All the information required to answer the questions can be found by effectively querying the CloudWatch logs.** So I think this question is just outdated with what the instance actually gives access to now.

**Answer: *redacted***

---

### 8. A critical alert was triggered when the attacker invoked an API to retrieve temporary credentials. What is the Event ID of the GetRole API call?
This is unfortunately another one where the instance doesn't have access. The first hint is "Examine CloudTrail logs for IAM-related API calls that would help an attacker understand role permissions", and I can only view cloudtrail logs from the last 90 days. Had to lookup the answer which is 78efd559-c626-4002-b458-088a4cc80e53. Hopefully they soon either update the instance to give access to GuardDuty, CloudTrail, etc, or they update the questions/investigation to account for that lack of access. I will definitely leave a review about it upon completion of the lab.

**Answer: 78efd559-c626-4002-b458-088a4cc80e53**


---

### 9. Analysis of HTTP User-Agent strings and CLI artifacts suggests the attacker was using a penetration-testing operating system. Which operating system was likely used by the attacker?

For this one we analyze the custom logs again and see that the most recent one had "User-Agent": "Mozilla/5.0 (X11; Kali Linux x86_64), which is obviously a very well-known pen testing Linux distribution:

(screenshots/5.png)

Also when decoding this in base64 (as well as some of the earlier "test.svg" files), we see that how the payload is structured:

(screenshots/base64.png)

The base64 xml code in the uploaded file embeds a DOCTYPE declaration defining a custom entity (&xxe;) that points at a file on the server's local filesystem: /proc/self/environ. The fileupload lambda function sees the ENTITY declaration, goes and reads the referenced file (/proc/self/environ) from the server's local disk, and substitutes that file's contents wherever &xxe; appears in the document in this case, - inside the SVG's <text> element.

We know that /proc/self/environ contains the Lambda execution environment's environment variables — critically, temporary AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN). Because the SVG now contains this data embedded as visible text, and if the function returns/stores/displays this processed SVG back in any way the attacker can retrieve, those credentials just leaked straight into the attacker's hands, which is obviously what occurred in this attack.

**With those leaked temporary credentials, the attacker was able to make their own authenticated AWS API calls, using the LambdaParser role's actual permissions - which is where "authenticated into the system and navigated internal resources" came from - the attack effectively tricked a poorly-configured XML parser into reading a sensitive local file and echoing its contents back**

**Answer: Kali**

---

<br>

**Complete:**

(screenshots/complete.png)


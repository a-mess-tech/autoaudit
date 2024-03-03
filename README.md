# Autoaudit

## Introduction

Autoaudit is a Unix forensics investigation tool to identify evidence of log tampering and identity attacks in the /var/log/wtmp, /var/log/btmp, and /var/run/utmp logs. Autoaudit is designed to be lightweight, extensible, and intuitive - written in Bash, it can run natively on any Unix system without dependencies. Finally, it can easily be run as a recurring cron job and configured to regularly send analysis results to a continuous monitoring solution or alert when anomalous activity is detected.

## Detections

Autoaudit will identify a variety of log tampering and identity attack indicators. This makes it a powerful tool for rapid analysis of the *tmp logs for forensic investigations. Here are the different indicators it's designed ot detect.

**** Log Tampering

- **Abnormal Record Types** - this function detects zeroed out logs by checking the record type (first column) in all input log sources. If an adversary conducted a log tampering attempt that zeroed out all fields of a log, the record type would be set to zero. Additionally, if an adversary attempted to manipulate the record type with any non-standard value, this function would alert.

- **Log Erasure** - this function identifies emptied fields in the *tmp logs beyond a normal threshold (which can be adjusted by the user). An adversary may use hexedit or utmpdump -r to erase all fields within a log entry but not erase the entry itself. This function will alert when it identifies an anomalous number of empty fields in a log entry.

- **Timestamp Manipulation** - this function detects manipulated and discontinuous timestamps in a log. The function compares all timestamps in the log and identifies if any are out of order - indicating potential log manipulation. An adversary may manipulate a logged event but not completely remove it in order to evade detection. This function will alert if it identifies a timestamp that has been manipulated and is now inconsistent with other entry timestamps. Additionally, this function will detect if a timestamp has been zeroed out (reset to epoch time in Unix - 1970-01-01 00:00:00). 

- **General File Manipulation** - this function detects discrepancies between the most recent entry time and file modification time. If an adversary were to manipulate a file with utmpdump -r or hexedit, then the file modification time would not match up with the most recent entry in the log. Outside of tampering, the file modification time will always match with the most recent log entry. This function will alert if the two timestamps are not equivalent.

#### Identity Attacks

Autoaudit is capable of rapidly identifying identity attacks in the /var/log/btmp logs.

- **Bruteforce Detection by User** - this function detects bruteforce or login attempts by users that are not registered on the system. It compares all failed logins with users found in /etc/passwd and identifies any attempted logins by users who are not registered on the system. This is useful to rapidly identify if credential stuffing or bruteforce attacks are being attempted on a system and their prevalence. 

- **Bruteforce by Time** - this function detects bruteforce or login attempts based on time entries. With sensitivity variables that can be defined by an admin (sens_num and sens_time), the function will identify suspicious numbers of failed logins within a certain time period. This is effective for rapidly identifying credential stuffing or bruteforce attacks. 

## How to Use

### Step-by-Step Instructions

#### Singular Execution

1. Download Autoaudit
2. Run the following to enable execution:
~~~~
> chmod +x ./autoaudit.sh
~~~~
3. Set the `LOG_FILES` and `IDENTITY_LOG_FILE` parameters in the first few lines of the script using your favorite text editor (*vim, duh!*)
    - The `LOG_FILES` variable establishes which files will be queried when evaluating log tampering. The `IDENTITY_LOG_FILE` variable will set which file will be queried when detecting identity attacks.
4. Run as root
> sudo ./autoaudit.sh
5. Select which variety of attack you'd like to evaluate (1 - Log Tampering / 2 - Identity Attacks)
6. View or save Autoaudit ouptut

#### Continuous Monitoring with Cron

1. Download Autoaudit
2. Run the following to enable execution:
> chmod +x ./autoaudit.sh
3. Set the `LOG_FILES` and `IDENTITY_LOG_FILE` parameters in the first few lines of the script using your favorite text editor (*it's still vim!*)
4. Set up your cron job with your desired evaluation module (1 - Log Tampering / 2 - Identity Attacks)
> 30 * * * * echo "1" | /home/kali/Desktop/autoaudit.sh > /home/kali/Desktop/test_output.txt 2>&1





# autoaudit

Autoaudit is a Unix forensics investigation tool to identify evidence of log tampering in the /var/log/wtmp, /var/log/btmp, and /var/run/utmp logs. Additionally, it can conduct analysis on the btmp log set to find evidence of identity attacks. Autoaudit is designed to be lightweight, extensible, and intuitive - written in Bash, it can run natively on any Unix system without dependencies. Finally, it can easily be run as a recurring cron job and configured to regularly send analysis results to a continuous monitoring solution or alert when anomalous activity is detected.

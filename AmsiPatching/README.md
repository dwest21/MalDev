# Preliminary Notes

Recently, I've taken up a little security research project and looked into the AntiMalwareScanInterface (AMSI) that is implemented within the Windows operating system. AMSI was implemented with the release of Windows 10, and it served as a way for applications and services to scan for malware. This becomes important when thinking about Endpoint Detection and Response/Antivirus (EDR/AV). The workflow for AMSI has been provided by Microsoft, and you can see it acts as an intermediary for security providers and applications: 

<img width="725" height="320" alt="image" src="https://github.com/user-attachments/assets/21def793-1872-4975-89e5-95f2952e3c6d" />

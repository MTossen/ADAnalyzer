0. Download the folder "ClickToRun"
1. Place it on the desktop of the Domain Controller
2. Right click "RunAsAdmin.Bat" and click 'Run as administrator'
3. The powershell script will then start collecting data.

The script runs through the following:

Domain controller information (Domain, servername, OS, RAM, TotalUsers & TotalGroups)
Active Directory Forest Level
Active Directory Domain Level
Active Directory Replicationstatus
Active Directory Trusts
Active Directory Federation Services
Active Directory Certificate Services
Active Directory Last BackupTime
Active Directory Recycle Bin
Audit policies
Azure AD-Sync
Default Domain password policy
DCDIAG on all domain controllers.
LAPS
SMB version 1
SYSVOL & NETLOGON folder permissions
Disabled users in Active Directory
Members of Administrators
Members of Domain Admins
Members of Enterprise Admins
Members of Schema Admins
Users with a password that haven't been changed in over 90 days
Users with a password that never expires
Users recently locked in Active Directory caused by bad password attempts

Creates a .csv-file that gives an overview of what permissions a user or group have in Active Directory. 
Type, Full name, Username, LastLogon, PasswordLastSet, PasswordNeverExpires, Enabled/Disabled, AD-groupmembership & a description of the group they are a member of.
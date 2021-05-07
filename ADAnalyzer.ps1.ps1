<# 
.DESCRIPTION  
The script is designed to analyse security settings & overall health of the Domain Controllers, and the domain itself. 
 
.OUTPUTS 
3 files will be placed on the desktop in a folder named 'Results'
File 1. DCAudit.txt - Holds all information about the domain controllers configuration & states.
File 2. UserAudit.txt holds all information about the AD-users.
File 3. DomainUserOverview.csv is a file that contains all memberships a user or group have in Active Directory.

.NOTES 
Make sure the script is executed in a elevated Powershell directly on one of the domain controllers

The scripts runs through the following:
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
 #> 

$Folder = Test-Path C:\Users\$env:username\Desktop\Results
If ($Folder)
{
Write-Host 'Folder already created.' -ForegroundColor Yellow
}
Else {
MKDIR C:\Users\$env:username\Desktop\Results | Out-null
}

# Starting Domain Controller exports

Import-Module ActiveDirectory
$ErrorActionPreference = "SilentlyContinue"
$Analyse = Test-Path C:\Users\$env:username\Desktop\Results\DCAudit.txt
If ($Analyse)
{
Remove-Item C:\Users\$env:username\Desktop\Results\DCAudit.txt
}

$ErrorActionPreference = "SilentlyContinue"
Start-Transcript -path C:\Users\$env:username\Desktop\Results\DCAudit.txt -append | out-null

Write-Host "

###########################################################################
Domain Controller Information
###########################################################################

" -ForegroundColor Red

$Serverlist = Get-ADDomainController -filter * | Select Hostname
$Data = @()

foreach ($Server in $Serverlist) {
$Count1 = (Get-ADUser -filter *).count
$Count2 = (Get-ADGroup -filter *).count
$MyObject = New-Object PSObject -Property @{
Domain = (Get-ADDomain).DNSRoot
Servername = $Server.Hostname
ForestLevel = (Get-ADForest).ForestMode
DomainLevel = (Get-ADDomain).DomainMode
OS = (Get-CimInstance -ComputerName $Server.Hostname -ClassName Win32_OperatingSystem).Caption
RAM = (Invoke-command $Server.Hostname {(systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()})
ADUsers = "$count1 users found in Active Directory"
ADGroups = "$count2 groups found in Active Directory"
}
$Data += $MyObject
}
$Data | FL Domain, Servername, OS, RAM, ForestLevel, DomainLevel, ADUsers, ADGroups


Write-Host "

###########################################################################
Active Directory Replicationstatus
###########################################################################

" -ForegroundColor Red

$DC = Get-ADDomainController -filter * | Select Hostname
$Replication = Foreach ($D in $DC) {Invoke-Command $D.Hostname {Get-ADReplicationFailure $using:D.Hostname | FL FailureCount, FirstFailureTime, Server}}


If ($Replication -eq $null)
{
Write-Host "There is only 1 domain controller" -ForegroundColor Yellow
}
Else
{
Repadmin /replsummary
}


Write-Host "

###########################################################################
Default Domain Password Policy
###########################################################################

" -ForegroundColor Red

$DomainPWD = Get-ADDefaultDomainPasswordPolicy
If ($DomainPWD) {
$DomainPWD | fl ComplexityEnabled, LockoutDuration, LockoutThreshold, MaxPasswordAge, MinPasswordLength, PasswordHistoryCount
}
If ($DomainPWD.MinPasswordLength -lt 10) {
Write-Host "MinPasswordLength is below 10 characters" -ForegroundColor Red
}
If ($DomainPWD.LockoutThreshold -lt 1)
{
Write-Host "LockOutThreshHold is set to 0. This allows brute-force attacks to be more efficient. Should be set to 5." -ForegroundColor Red
}
if ($DomainPWD.ComplexityEnabled -eq $false) {
Write-Host "Password complexity is not ENABLED." -ForegroundColor Red
}
If ($DomainPWD.PasswordHistoryCount -lt 10) {
Write-Host "Password History is below 10."
}


Write-Host "

###########################################################################
Active Directory Trusts
###########################################################################

" -ForegroundColor Red

$DC = Get-ADDomainController -Filter * | Select Hostname
Foreach ($D in $DC) {
$Role = Get-ADTrust -Filter *
$Name = $D.Hostname
If ($Role -eq $null)
{
Write-Host "

No trusts found in 'Active Directory Domains & Trusts' on: $Name

"
}
Else {

Write-Host "
Server: $Name
Trusts found!
$Role

"
}}



Write-Host "

###########################################################################
Active Directory Federation Services
###########################################################################

" -ForegroundColor Red

$DC = Get-ADDomainController -Filter * | Select Hostname
$ROle = Foreach ($D in $DC) {Invoke-Command $D.Hostname {Get-WindowsFeature ADFS-Federation | Where {$_.Installed -EQ "$true"}}}

$Name = $D.Hostname
If ($Role)
{
Write-Host "

The Active Directory Federation Services role is installed on: $Name.

"
}
Else {

Write-Host "
Server: $Name
The Active Directory Federation Services role is NOT installed on: $Name.

"
}


Write-Host "

###########################################################################
Active Directory Certificate Services
###########################################################################

" -ForegroundColor Red

$DC = Get-ADDomainController -Filter * | Select Hostname
$ROle = Foreach ($D in $DC) {Invoke-Command $D.Hostname {Get-WindowsFeature AD-Certificate | Where {$_.Installed -EQ "$true"}}}
$Name = $D.Hostname
If ($Role)
{
Write-Host "
Server: $Name
The Active Directory Certificate role is installed on: $Name."
$Cert = Get-ChildItem "Cert:\LocalMachine\My"
If ($Cert) {
Set-Location "Cert:\LocalMachine\My"
$Cert | Select FriendlyName, NotAfter, NotBefore, Thumbprint
}
}
Else {

Write-Host "
Server: $Name
The Active Directory Certificate role is NOT installed on: $Name.

"
}


Write-Host "


###########################################################################
Azure AD Account & Last Sync
###########################################################################


" -ForegroundColor Red

$MSOLUser = Get-ADUser -filter * -Properties * | Where {$_.SamAccountName -like "MSOL_*"} | fl SamAccountName, PasswordLastSet, PasswordNeverExpires, @{Name='LastAzureSync';Expression={[DateTime]::FromFileTime($_.LastLogon)}}, @{Name="Installed on:";Expression={$_.Description}}
$SYNCUser = Get-ADUser -filter * -Properties * | Where {$_.SamAccountName -like "SYNC_*"} | fl SamAccountName, PasswordLastSet, PasswordNeverExpires, @{Name='LastAzureSync';Expression={[DateTime]::FromFileTime($_.LastLogon)}}, @{Name="Installed on:";Expression={$_.Description}}

If ($MSOLUser) 
{
$MSOLUser
}
Else
{
If ($SYNCUser)
{
$SYNCUser
}
else {
Write-Host "No Azure Sync accounts found in AD" -ForegroundColor Red
}
}




Write-Host "


###########################################################################
AD Recycle Bin
###########################################################################


" -ForegroundColor Red

If ((Get-ADOptionalFeature -Filter {Name -like "Recycle*"}).EnabledScopes) 
{
Write-Host 'Recycle Bin enabled' -ForegroundColor Green
}
else
{
Write-Host 'Recycle Bin DISABLED
Recommendation: Enable AD Recycle Bin. This will allow AD to restore deleted AD-objects instantly.' -ForegroundColor Red
}

Write-Host "


###########################################################################
LAPS
###########################################################################


" -ForegroundColor Red

$Domain = Get-ADDomainController | Select DefaultPartition
$Domain2 = $Domain.DefaultPartition
$LAPS = Get-ADObject "CN=ms-mcs-admpwd,cn=Schema,CN=Configuration,$Domain2" -ErrorAction Ignore

if ($LAPS) {
Write-Host "LAPS IMPLEMENTED" -ForegroundColor Green
}
else 
{
Write-Host "LAPS NOT IMPLEMENTED
Recommendation: Implement LAPS to prevent unauthorized access to workstations." -ForegroundColor Red
}




Write-Host "


###########################################################################
SMB version 1
###########################################################################


" -ForegroundColor Red

$DC = Get-ADDomainController -Filter * | Select Hostname
Foreach ($D in $DC) {
$SMB = Get-SmbServerConfiguration | Select EnableSMB1Protocol
$Hostname = $D.Hostname
If ($SMB.EnableSMB1Protocol -eq $true) 
{
Write-Host "
SMBv1 is enabled on $Hostname. The protocol is over 30 years old. SMBv2 should be introduced to the domain instead.
" -ForegroundColor red
}
Else {
Write-Host "SMBv1 is DISABLED on $Hostname" -ForegroundColor Green
 }
}



Write-Host "


###########################################################################
Audit Security Log Policies
###########################################################################


" -ForegroundColor Red

auditpol /get /category:* | findstr "Sucess and failure No"



Write-Host "

###########################################################################
SYSVOL Permissions
###########################################################################

" -ForegroundColor Yellow


$DC = Get-ADDomainController | Select Hostname
$DCPath = $DC.Hostname

$Path = "\\$DCPath\SysVol"

$FolderPath = Dir -Directory -Path $Path -Force
$Report = @()

    $Acl = Get-Acl -Path $Path
    foreach ($Access in $acl.Access)
        {
            $Properties = [ordered]@{'FolderName'=$Path;'ADGroup or User'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited}
            $Report += New-Object -TypeName PSObject -Property $Properties
        }

$Report

Write-Host "

###########################################################################
NETLOGON Permissions
###########################################################################

" -ForegroundColor Yellow


$DC = Get-ADDomainController | Select Hostname
$DCPath = $DC.Hostname

$Path = "\\$DCPath\NETLOGON"

$FolderPath = Dir -Directory -Path $Path -Force
$Report = @()

    $Acl = Get-Acl -Path $Path
    foreach ($Access in $acl.Access)
        {
            $Properties = [ordered]@{'FolderName'=$Path;'ADGroup or User'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited}
            $Report += New-Object -TypeName PSObject -Property $Properties
        }

$Report



Write-Host "

###########################################################################
Active Directory backup timestamps
###########################################################################

" -ForegroundColor Red

    function Convert-TimeToDays {
        [CmdletBinding()]
        param (
            $StartTime,
            $EndTime,
            [string] $Ignore = '*1601*'
        )
        if ($null -ne $StartTime -and $null -ne $EndTime) {
            try {
                if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                    $Days = (NEW-TIMESPAN -Start $StartTime -End $EndTime).Days
                }
            } catch {}
        } elseif ($null -ne $EndTime) {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (NEW-TIMESPAN -Start (Get-Date) -End ($EndTime)).Days
            }
        } elseif ($null -ne $StartTime) {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (NEW-TIMESPAN -Start $StartTime -End (Get-Date)).Days
            }
        }
        return $Days
    }
    function Get-WinADLastBackup {
        [cmdletBinding()]
        param(
            [string[]] $Domains
        )
        $NameUsed = [System.Collections.Generic.List[string]]::new()
        [DateTime] $CurrentDate = Get-Date
        if (-not $Domains) {
            try {
                $Forest = Get-ADForest -ErrorAction Stop
                $Domains = $Forest.Domains
            } catch {
                Write-Warning "Get-WinADLastBackup - Failed to gather Forest Domains $($_.Exception.Message)"
            }
        }
        foreach ($Domain in $Domains) {
            try {
                [string[]]$Partitions = (Get-ADRootDSE -Server $Domain -ErrorAction Stop).namingContexts
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType] $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
                [System.DirectoryServices.ActiveDirectory.DirectoryContext] $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Domain)
                [System.DirectoryServices.ActiveDirectory.DomainController] $domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
            } catch {
                Write-Warning "Get-WinADLastBackup - Failed to gather partitions information for $Domain with error $($_.Exception.Message)"
            }
            $Output = ForEach ($Name in $Partitions) {
                if ($NameUsed -contains $Name) {
                    continue
                } else {
                    $NameUsed.Add($Name)
                }
                $domainControllerMetadata = $domainController.GetReplicationMetadata($Name)
                $dsaSignature = $domainControllerMetadata.Item("dsaSignature")
                $LastBackup = [DateTime] $($dsaSignature.LastOriginatingChangeTime)
                [PSCustomObject] @{
                    Domain            = $Domain
                    NamingContext     = $Name
                    LastBackup        = $LastBackup
                    LastBackupDaysAgo = - (Convert-TimeToDays -StartTime ($CurrentDate) -EndTime ($LastBackup))
                }
            }
            $Output
        }
    }


    $LastBackup = Get-WinADLastBackup
    $LastBackup | Format-Table -AutoSize

Write-Host "


###########################################################################
DCDIAG on all Active Directory Domain Controller(s)
###########################################################################

" -ForegroundColor Red

$DC = Get-ADDomainController -Filter * | Select Hostname
Foreach ($D in $DC) {
$hostname = $D.Hostname
DCDIAG /S:$hostname
}


Stop-Transcript | out-null


# Starting AD-User information export

$ErrorActionPreference = "SilentlyContinue"
$Analyse = Test-Path C:\Users\$env:username\Desktop\Results\UserAudit.txt
If ($Analyse)
{
Remove-Item C:\Users\$env:username\Desktop\Results\UserAudit.txt
}

$ErrorActionPreference = "SilentlyContinue"
Start-Transcript -path C:\Users\$env:username\Desktop\Results\UserAudit.txt -append | out-null


Write-Host "

###########################################################################
Users with a password that haven't been changed in over 90 days
###########################################################################

" -ForegroundColor Red


$Date = (Get-Date).AddDays(-90)
(Get-ADUser -filter {PasswordLastSet -GT $Date} -Properties *).count


Write-Host "

###########################################################################
Disabled accounts in Active Directory
###########################################################################

" -ForegroundColor Red
(Get-ADUser -filter * -Properties * | Where {$_.Enabled -EQ $false}).count

Write-Host "

###########################################################################
Members of Domain Admins
###########################################################################

" -ForegroundColor Red

$DomainAdmins = Get-ADGroup "Domain Admins" | Select SamAccountName

foreach ($Admin in $DomainAdmins) {
    Get-ADGroupMember -Identity $Admin.SamAccountName |
      Get-ADUser -Properties * |
        FL DisplayName, SamAccountName, PasswordLastSet, LastLogonDate
        }
Write-Host "

###########################################################################
Members of Enterprise Admins
###########################################################################

" -ForegroundColor Red

$EnterpriseAdmins = Get-ADGroup "Enterprise Admins" | Select SamAccountName

foreach ($Admin in $EnterpriseAdmins) {
    Get-ADGroupMember -Identity $Admin.SamAccountName |
        Get-ADUser -Properties * |
        FL DisplayName, SamAccountName, PasswordLastSet, LastLogonDate
        }


Write-Host "

###########################################################################
Members of Administrators
###########################################################################

" -ForegroundColor Red

$Admins = Get-ADGroup "Administrators" | Select SamAccountName

foreach ($Admin in $Admins) {
    Get-ADGroupMember -Identity $Admin.SamAccountName |
       Get-ADUser -Properties * |
        FL DisplayName, SamAccountName, PasswordLastSet, LastLogonDate
        }


Write-Host "

###########################################################################
Members of Schema Admins
###########################################################################

" -ForegroundColor Red

$SchemaAdmins = Get-ADGroup "Schema Admins" | Select SamAccountName

foreach ($Admin in $SchemaAdmins) {
    Get-ADGroupMember -Identity $Admin.SamAccountName |
        Get-ADUser -Properties * |
        FL DisplayName, SamAccountName, PasswordLastSet, LastLogonDate
        }



Write-Host "

###########################################################################
Users with a password that never expires
###########################################################################

" -ForegroundColor Red
(Get-ADUser -filter * -Properties * | Where {$_.PasswordNeverExpires -eq $true}).count




Write-Host "

###########################################################################
Users locked because of bad password attempts
###########################################################################

" -ForegroundColor Red

$DC = Get-ADDomainController -Filter * | Select Hostname 
$properties = @(
    @{n='User';e={$_.Properties[0].Value}},
    @{n='Locked by';e={$_.Properties[1].Value}},
    @{n='TimeStamp';e={$_.TimeCreated}},
    @{n='DCName';e={$_.Properties[4].Value}}
)
Foreach ($D in $DC)
{
$Name = $D.Hostname
$Events = Get-WinEvent -ComputerName $D.Hostname -FilterHashTable @{LogName='Security'; ID=4740} | 
fl $properties

If ($Events)
{
$Events
}
Else
{
Write-Host "No accounts was recently locked in AD on DC: $Name 



" -ForegroundColor Yellow
}
}

Stop-Transcript | out-null


Write-Host "

###########################################################################
Exporting AD permissions. . . . . .
###########################################################################

" -ForegroundColor Yellow



$ADMatrix = Test-Path C:\Users\$env:username\Desktop\Results\DomainUserOverview.csv
If ($ADMAtrix)
{
Remove-Item C:\Users\$env:username\Desktop\Results\DomainUserOverview.csv
}

Get-ADGroup -filter * -Properties * | Select SamAccountName, Description |
Export-csv C:\Users\$ENV:Username\Desktop\ADGroups.csv -NoTypeInformation -Encoding UTF8


$ErrorActionPreference= 'silentlycontinue'
$csv = Import-csv C:\Users\$ENV:Username\Desktop\ADGroups.csv 
foreach ($row in $csv) {
    Get-ADGroupMember -Identity $row.SamAccountName |
        Get-ADObject -Properties * | Where ObjectClass -NE "Computer" |
        Select-Object @{Name="Type";Expression={$_.ObjectClass}},
		    @{Name="Full Name";Expression={$_.DisplayName}},
            @{Name="Username";Expression={$_.SamAccountName}},
			@{Name="Last Logon";Expression={(Get-ADUser -property LastLogonDate $_.SamAccountName).LastLogonDate}},
			@{Name="PasswordChanged";Expression={(Get-ADUser -property PasswordLastSet $_.SamAccountName).PasswordLastSet}},
            @{Name="PasswordNeverExpires";Expression={(Get-ADUser -property PasswordNeverExpires $_.SamAccountName).PasswordNeverExpires}},
            @{Name="Enabled";Expression={$_.Enabled}},
            @{Name="Member Of";Expression={$row.SamAccountName}},
            @{Name="Group Description";Expression={$row.Description}} |
        Export-csv "C:\Users\$env:username\Desktop\Results\DomainUserOverview.csv" -NoTypeInformation -Encoding UNICODE -Append}
        Remove-Item "C:\Users\$ENV:Username\Desktop\ADGroups.csv" -Force
		
		
		

 
		Write-Host "

###########################################################################
#                              COMPLETED                                  #
#                                                                         #
#      Exported data can be found here: $home\Desktop\Results                  
#                                                                         #
#                                                                         #
#                                                                         #
###########################################################################

" -ForegroundColor Green

Stop-Transcript | out-null
timeout 10 | out-null
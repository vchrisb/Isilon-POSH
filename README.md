# Isilon-POSH

EMC Isilon Platform API implementation in Powershell

=====

This is an inofficial Powershell module that allows you to manage your EMC Isilon Scale-Out NAS systems by Powershell. Only a subset of the  Isilon Platform API is currently implemented. 

#### Requirements:
* Powershell 3.0 and newer
* Isilon OneFS 7.1.0.0 and newer

#### Implemented Commands

* Get-isiNFSExports
* Get-isiQuotas
* Get-isiQuotasSummary
* Get-isiSession
* Get-isiSessioninfo
* Get-isiSMBOpenfiles
* Get-isiSMBOpenfilesSummary
* Get-isiSMBSettingsGlobal
* Get-isiSMBSettingsGlobalSummary
* Get-isiSMBSettingsShares
* Get-isiSMBSettingsSharesSummary
* Get-isiSMBShares
* Get-isiSMBSharesSummary
* Get-isiSyncJobs
* Get-isiSyncJobsSummary
* Get-isiSyncPolicies
* Get-isiSyncPoliciesSummary
* Get-isiSyncReports
* Get-isiSyncReportsSummary
* Get-isiSyncTargetPolicies
* Get-isiSyncTargetPoliciesSummary
* Get-isiZones
* Get-isiZonesSummary
* New-isiQuotas
* New-isiSession
* New-isiSMBShares
* New-isiZones
* Remove-isiQuotas
* Remove-isiSession
* Remove-isiSMBShares
* Remove-isiSyncPolicies
* Remove-isiZones
* Send-isiAPI
* Set-isiQuotas
* Set-isiSMBShares
* Set-isiSyncPolicies
* Set-isiZones

#### Examples:
```PowerShell
Import-Module IsilonPlatform

New-isiSession -ComputerName isilonc1.emc.lab -Username root -Password a
New-isiSession -ComputerName 192.168.10.100 -Username root -Password a -Cluster isilonc2.emc.lab

Get-isiSMBShares
Get-isiSMBShares -Cluster isilonc2.emc.lab
isilonc1.emc.lab, isilonc2.emc.lab | Get-isiSMBShares
```
#### DISCLAIMER:
This Powershell Module is not supported. Use at your own risk!

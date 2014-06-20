# Isilon-POSH

EMC Isilon Platform API implementation in Powershell

=====

This is an inofficial (not by EMC) Powershell module that allows you to manage your EMC Isilon Scale-Out NAS systems by Powershell. Only a subset of the  Isilon Platform API (REST) is currently implemented. 

More Information clould be found in these blog posts:
* http://blog.banck.net/2013/12/isilon-rest-api-using-powershell-part-1.html
* http://blog.banck.net/2014/01/isilon-rest-api-using-powershell-part-2.html

#### Requirements
* Powershell 3.0 and newer
* Isilon OneFS 7.1.0.0 and newer

#### Installation

Copy the folder 'IsilonPlatform' and 'SSLValidation' to the desired module path.
You can find the configured Powershell module paths in the variable '$env:PSModulePath'.

#### Examples
```PowerShell
Import-Module IsilonPlatform

New-isiSession -ComputerName isilonc1.emc.lab -Username root -Password a
New-isiSession -ComputerName 192.168.10.100 -Username root -Password a -Cluster isilonc2.emc.lab

Get-isiSMBShares
Get-isiSMBShares -Cluster isilonc2.emc.lab
isilonc1.emc.lab, isilonc2.emc.lab | Get-isiSMBShares
```

#### SSL Validation
If you are using self signed certificates on your Isilon you need to disable SSL validation in powershell.
This could be accomplished by code from Matthew Graeber. (http://poshcode.org/3606)
The code could also be found in this repository.

```PowerShell
Import-Module SSLValidation
Disable-SSLValidation
```

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

#### DISCLAIMER
This Powershell Module is not supported. Use at your own risk!

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

#### Features
* Websession support, no need to store password
* PowerShell pipeline support
* concurrently connecting to multiple Isilon clusters
* 100% of the Platform API for OneFS v7.2 covered
* confirmation and error handling

#### Installation

Copy the folder 'IsilonPlatform' and 'SSLValidation' to the desired module path.
You can find the configured Powershell module paths in the variable 
```PowerShell
$env:PSModulePath
```

#### Examples
```PowerShell
Import-Module IsilonPlatform

# connect Isilon using FQDN
New-isiSession -ComputerName isilonc1.emc.lab -Username root -Password a

# connect Isilon using IP address and configure a Cluster name
New-isiSession -ComputerName 192.168.10.100 -Username root -Password a -Cluster isilonc2

# Get all SMB shares for default cluster
Get-isiSmbShares

# Get all SMB shares for cluster isilonc2.emc.lab
Get-isiSmbShares -Cluster isilonc2.emc.lab

# Get all SMB shares for all connected cluster
Get-isiSession | Get-isiSmbShares

# create new SMB share
New-isiSmbShare -name HR -path '/ifs/data/HR'

# add a describtion to all SMB shares that have 'test' in there share name
Get-isiSmbShares | where name -like '*test*' | Set-isiSmbShare -description 'This is a Test Share'
```

#### SSL Validation
If you are using self signed certificates on your Isilon you need to disable SSL validation in powershell.
This could be accomplished by code from Matthew Graeber. (http://poshcode.org/3606)
The code could also be found in this repository.

```PowerShell
Import-Module SSLValidation
Disable-SSLValidation
```

#### DISCLAIMER
This Powershell Module is not supported. Use at your own risk!

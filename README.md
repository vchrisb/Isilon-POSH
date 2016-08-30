# Isilon-POSH

EMC Isilon Platform API implementation in Powershell

=====

This is an inofficial (not by EMC) Powershell module that allows you to manage your EMC Isilon Scale-Out NAS systems by Powershell.

More Information clould be found in these blog posts:
* https://banck.net/2013/12/isilon-rest-api-using-powershell-part-1.html
* https://banck.net/2014/01/isilon-rest-api-using-powershell-part-2.html
* https://banck.net/2014/08/tcp-connection-hanging-in-close_wait-when-using-invoke-restmethod-with-put-or-delete/

Most of the cmdlets are generated using [Isilon-POSH-Generator](https://github.com/vchrisb/Isilon-POSH-Generator). Please see [Contribution](#contribution) for more information.

### Requirements
* Powershell 3.0 and newer
* Isilon OneFS 7.1.0.0 and newer

### Features
* Websession support, no need to store password
* PowerShell pipeline support
* concurrently connecting to multiple Isilon clusters
* 99% of the Platform API for OneFS v8.0 covered
* confirmation and error handling

### Installation

#### Windows

Copy the folder `IsilonPlatform` and `SSLValidation` to the desired module path.
You can find the configured Powershell module paths in the variable 
```PowerShell
$env:PSModulePath
```

#### Linux

[Linux PowerShell installation instructions](https://github.com/PowerShell/PowerShell/blob/master/docs/installation/linux.md#paths) can be found in the PowerShell GitHub Repo.
Make sure that you have `libcurl3` (for Ubuntu 16.04) or equivalent installed.

Copy the folder `IsilonPlatform` to one of the [supported module paths](https://github.com/PowerShell/PowerShell/blob/master/docs/installation/linux.md#paths).
For example the shared modules path: `/usr/local/share/powershell/Modules/`

##### SSL certificate

The `SSLValidation` module does not work on linux. To be able to connect to the Isilon cluster, you will have to trust the SSL certificate on the linux client.
Make sure that the `ComputerName` is identical to the `common name` in the SSL certificate, when connecting to the cluster.
If you are using a self-signed certificate, you will need to replace it with the `common name` configured to match the hostname, used to connect to the Isilon. This should be a DNS Record pointing to the SmartConnect service IP address or the IP itself. A procedure can be found in the [Web Administration Guide](http://www.emc.com/collateral/TechnicalDocument/docu65068.pdf)

Retrieving and installing the certificate can be accomplished on Ubuntu 16.04 as followed:
```sh
echo -n | openssl s_client -connect <hostname>:8080 -showcerts 2>/dev/null | openssl x509 -outform PEM > isilon.crt
sudo cp isilon.crt /usr/share/ca-certificates/
echo "isilon.crt" | sudo tee --append /etc/ca-certificates.conf 
sudo update-ca-certificates
```

`curl https://<hostname>:8080/session/1/session` shouldn't print any error if successful.

#### macOS

tbd

### Examples
```PowerShell
Import-Module IsilonPlatform

# connect Isilon using FQDN
New-isiSession -ComputerName isilonc1.emc.lab

# connect Isilon using IP address and configure a Cluster name
New-isiSession -ComputerName 192.168.10.100 -Cluster isilonc2

# Get all SMB shares for default cluster
Get-isiSmbShares

# Get all SMB shares for cluster isilonc2.emc.lab
Get-isiSmbShares -Cluster isilonc2

# Get all SMB shares for all connected cluster
Get-isiSession | Get-isiSmbShares

# Backup all SMB shares to json file for default session
Get-isiSmbShares | ConvertTo-Json | Out-File shares.json

# create new SMB share
New-isiSmbShare -name HR -path '/ifs/data/HR'

# add a describtion to all SMB shares that have 'test' in there share name
Get-isiSmbShares | where name -like '*test*' | Set-isiSmbShare -description 'This is a Test Share'

# limit Get-isiSmbShares to only receive 1000 shares
$shares, $token = Get-isiSmbShares -limit 1000
# pass the saved token and receive the next 1000 shares, repeat until $token is empty
$next_shares, $token = Get-isiSmbShares -resume $token
$shares += $next_shares

# print help for function New-isiSmbShares
Get-Help -Detailed New-isiSmbShares
```

### Known Issues

**receiving large amount of data fails**  
You may get following error:  
`Error during serialization or deserialization using the JSON JavaScriptSerializer. The length of the string exceeds the value set on the maxJsonLength property.`  
This is due to `ConvertFrom-Json` only supports `JSON` smallen than 2 MB and it couldn't be raised for that Cmdlet.  
To overcome this limitation you can use the `limit` and corresponding `resume`flag. See example above.

**Cmdlet `get-isiSmbOpenfiles` does return 1000 objects at max**  
The resource `/platform/1/protocols/smb/openfiles` does return at maximum `1000` openfiles by default  
To overcome this limitation you can use the `limit` and corresponding `resume`flag. See example above.

### SSL Validation
If you are using self signed certificates on your Isilon you need to disable SSL validation in powershell.
This could be accomplished by code from Matthew Graeber. (http://poshcode.org/3606)
The code could also be found in this repository.

```PowerShell
Import-Module SSLValidation
Disable-SSLValidation
```

### Things to do
* Add support for API endpoints with three parameters (e.g. `/3/network/groupnets/<GROUPNET>/subnets/<SUBNET>/pools/<POOL>`)
* testing
* testing

### Contribution

Happy to get PRs! 
Please open an issue before sending a PR and for each fix only one PR.

Following files are are automatically generated via [Isilon-POSH-Generator](https://github.com/vchrisb/Isilon-POSH-Generator):

* IsilonPlatformGet.ps1
* IsilonPlatformNew.ps1
* IsilonPlatformRemove.ps1
* IsilonPlatformSet.ps1

To discuss enhancements and bugs open an issue in this repo and PRs for these files will have to go to the [Isilon-POSH-Generator](https://github.com/vchrisb/Isilon-POSH-Generator) repo.

### DISCLAIMER
This Powershell Module is not supported. Use at your own risk!

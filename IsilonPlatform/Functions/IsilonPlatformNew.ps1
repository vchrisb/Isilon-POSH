# The MIT License
#
# Copyright (c) 2016 Christopher Banck.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#Build using Isilon OneFS build: B_8_0_0_037(RELEASE)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


function New-isiAntivirusPolicies{
<#
.SYNOPSIS
	New Antivirus Policies

.DESCRIPTION
	Create new antivirus scan policies.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/antivirus/policies" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAntivirusPolicies

function New-isiAntivirusScan{
<#
.SYNOPSIS
	New Antivirus Scan

.DESCRIPTION
	Manually scan a file.

.PARAMETER file
	The full path of the file to scan.

.PARAMETER force_run
	Forces the scan to run regardless of whether the files were recently scanned. The default value is true.

.PARAMETER policy
	The ID of the policy to use for the scan. By default, the scan will use the MANUAL policy.

.PARAMETER report_id
	The ID for the report for this scan. A report ID will be generated if one is not provided.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$force_run,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$report_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/antivirus/scan" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAntivirusScan

function New-isiAntivirusServers{
<#
.SYNOPSIS
	New Antivirus Servers

.DESCRIPTION
	Create new antivirus servers.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/antivirus/servers" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAntivirusServers

function New-isiAuditTopics{
<#
.SYNOPSIS
	New Audit Topics

.DESCRIPTION
	Create a new audit topic.

.PARAMETER max_cached_messages
	Specifies the maximum number of messages that can be sent and received at the same time. Messages that are sent and received at the same time can be lost if a system crash occurs. You can prevent message loss by setting this property to 0, which sets audit logs to synchronous.

.PARAMETER name
	Specifies the name of the audit topic.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$max_cached_messages,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/audit/topics" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuditTopics

function New-isiAuthGroups{
<#
.SYNOPSIS
	New Auth Groups

.DESCRIPTION
	Create a new group.

.PARAMETER gid
	Specifies the numeric group identifier.

.PARAMETER members
	Specifies the members of the group.

.PARAMETER name
	Specifies the group name.

.PARAMETER sid
	Specifies the security identifier.

.PARAMETER provider
	Optional provider type.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$members,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$sid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters.Remove('provider') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/groups" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthGroups

function New-isiAuthGroupMembers{
<#
.SYNOPSIS
	New Auth Group Members

.DESCRIPTION
	Add a member to the group.

.PARAMETER group_id
	Group group_id

.PARAMETER group_name
	Group group_name

.PARAMETER id
	Specifies the serialized form of a persona, which can be 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', or 'SID:S-1-1'.

.PARAMETER name
	Specifies the persona name, which must be combined with a type.

.PARAMETER type
	Specifies the type of persona, which must be combined with a name.
	Valid inputs: user,group,wellknown

.PARAMETER provider
	Filter group members by provider.

.PARAMETER access_zone
	Filter group members by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$group_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$group_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('user','group','wellknown')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('group_id')){
				$parameter1 = $group_id
				$BoundParameters.Remove('group_id') | out-null
			} else {
				$parameter1 = $group_name
				$BoundParameters.Remove('group_name') | out-null
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters.Remove('provider') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/groups/$parameter1/members" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthGroupMembers

function New-isiAuthMappingIdentities{
<#
.SYNOPSIS
	New Auth Mapping Identities

.DESCRIPTION
	Manually set or modify a mapping between two personae.

.PARAMETER source
	Specifies the source identity.

.PARAMETER targets
	

.PARAMETER 2way
	Create a bi-directional mapping from source to target and target to source.

.PARAMETER replace
	Replace existing mappings.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$source,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$targets,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$2way,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$replace,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($2way){
				$queryArguments += '2way=' + $2way
				$BoundParameters.Remove('2way') | out-null
			}
			if ($replace){
				$queryArguments += 'replace=' + $replace
				$BoundParameters.Remove('replace') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/mapping/identities" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthMappingIdentities

function New-isiAuthMappingIdentities{
<#
.SYNOPSIS
	New Auth Mapping Identity

.DESCRIPTION
	Manually set or modify a mapping between two personae.

.PARAMETER id
	Source id

.PARAMETER name
	Source name

.PARAMETER type
	Desired mapping target to fetch/generate.
	Valid inputs: uid,gid,sid

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('uid','gid','sid')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$queryArguments = @()
			if ($type){
				$queryArguments += 'type=' + $type
				$BoundParameters.Remove('type') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/mapping/identities/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.identities
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthMappingIdentities

function New-isiAuthProvidersAdsv1{
<#
.SYNOPSIS
	New Auth Providers Ads

.DESCRIPTION
	Create a new ADS provider.

.PARAMETER account
	Specifies the machine account name when creating a SAM account with Active Directory. The default cluster name is called 'default'.

.PARAMETER allocate_gids
	Allocates an ID for an unmapped Active Directory (ADS) group. ADS groups without GIDs can be proactively assigned a GID by the ID mapper. If the ID mapper option is disabled, GIDs are not proactively assigned, and when a primary group for a user does not include a GID, the system may allocate one. 

.PARAMETER allocate_uids
	Allocates a user ID for an unmapped Active Directory (ADS) user. ADS users without UIDs can be proactively assigned a UID by the ID mapper. IF the ID mapper option is disabled, UIDs are not proactively assigned, and when an identify for a user does not include a UID, the system may allocate one.

.PARAMETER assume_default_domain
	Enables lookup of unqualified user names in the primary domain.

.PARAMETER authentication
	Enables authentication and identity management through the authentication provider.

.PARAMETER check_online_interval
	Specifies the time in seconds between provider online checks.

.PARAMETER controller_time
	Specifies the current time for the domain controllers.

.PARAMETER create_home_directory
	Automatically creates a home directory on the first login.

.PARAMETER dns_domain
	Specifies the DNS search domain. Set this parameter if the DNS search domain has a unique name or address.

.PARAMETER domain_offline_alerts
	Sends an alert if the domain goes offline.

.PARAMETER findable_groups
	Sets list of groups that can be resolved.

.PARAMETER findable_users
	Sets list of users that can be resolved.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER ignored_trusted_domains
	Includes trusted domains when 'ignore_all_trusts' is set to false.

.PARAMETER ignore_all_trusts
	If set to true, ignores all trusted domains.

.PARAMETER include_trusted_domains
	Includes trusted domains when 'ignore_all_trusts' is set to true.

.PARAMETER kerberos_hdfs_spn
	Determines if connecting through HDFS with Kerberos.

.PARAMETER kerberos_nfs_spn
	Determines if connecting through NFS with Kerberos.

.PARAMETER ldap_sign_and_seal
	Enables encryption and signing on LDAP requests.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER lookup_domains
	Limits user and group lookups to the specified domains.

.PARAMETER lookup_groups
	Looks up AD groups in other providers before allocating a group ID.

.PARAMETER lookup_normalize_groups
	Normalizes AD group names to lowercase before look up.

.PARAMETER lookup_normalize_users
	Normalize AD user names to lowercase before look up.

.PARAMETER lookup_users
	Looks up AD users in other providers before allocating a user ID.

.PARAMETER machine_password_changes
	Enables periodic changes of the machine password for security.

.PARAMETER machine_password_lifespan
	Sets maximum age of a password in seconds.

.PARAMETER name
	Specifies the Active Directory provider name.

.PARAMETER node_dc_affinity
	Specifies the domain controller for which the node has affinity.

.PARAMETER node_dc_affinity_timeout
	Specifies the timeout for the domain controller for which the local node has affinity.

.PARAMETER nss_enumeration
	Enables the Active Directory provider to respond to 'getpwent' and 'getgrent' requests.

.PARAMETER organizational_unit
	Specifies the organizational unit.

.PARAMETER password
	Specifies the password used during domain join.

.PARAMETER restrict_findable
	Check the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER sfu_support
	Specifies whether to support RFC 2307 attributes on ADS domain controllers.
	Valid inputs: none,rfc2307

.PARAMETER store_sfu_mappings
	Stores SFU mappings permanently in the ID mapper.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER user
	Specifies the user name that has permission to join a machine to the given domain.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$account,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allocate_gids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allocate_uids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$assume_default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$controller_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$dns_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$domain_offline_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$ignored_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$ignore_all_trusts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$include_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$kerberos_hdfs_spn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$kerberos_nfs_spn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$ldap_sign_and_seal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][array]$lookup_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$lookup_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$lookup_normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$lookup_normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$lookup_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$machine_password_changes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$machine_password_lifespan,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$node_dc_affinity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$node_dc_affinity_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$nss_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$organizational_unit,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateSet('none','rfc2307')][string]$sfu_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$store_sfu_mappings,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][array]$unfindable_users,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/ads" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersAdsv1
Set-Alias New-isiAuthProvidersAds -Value New-isiAuthProvidersAdsv1
Export-ModuleMember -Alias New-isiAuthProvidersAds

function New-isiAuthProvidersAdsv3{
<#
.SYNOPSIS
	New Auth Providers Ads

.DESCRIPTION
	Create a new ADS provider.

.PARAMETER account
	Specifies the machine account name when creating a SAM account with Active Directory. The default cluster name is called 'default'.

.PARAMETER allocate_gids
	Allocates an ID for an unmapped Active Directory (ADS) group. ADS groups without GIDs can be proactively assigned a GID by the ID mapper. If the ID mapper option is disabled, GIDs are not proactively assigned, and when a primary group for a user does not include a GID, the system may allocate one. 

.PARAMETER allocate_uids
	Allocates a user ID for an unmapped Active Directory (ADS) user. ADS users without UIDs can be proactively assigned a UID by the ID mapper. IF the ID mapper option is disabled, UIDs are not proactively assigned, and when an identify for a user does not include a UID, the system may allocate one.

.PARAMETER assume_default_domain
	Enables lookup of unqualified user names in the primary domain.

.PARAMETER authentication
	Enables authentication and identity management through the authentication provider.

.PARAMETER check_online_interval
	Specifies the time in seconds between provider online checks.

.PARAMETER controller_time
	Specifies the current time for the domain controllers.

.PARAMETER create_home_directory
	Automatically creates a home directory on the first login.

.PARAMETER dns_domain
	Specifies the DNS search domain. Set this parameter if the DNS search domain has a unique name or address.

.PARAMETER domain_offline_alerts
	Sends an alert if the domain goes offline.

.PARAMETER findable_groups
	Sets list of groups that can be resolved.

.PARAMETER findable_users
	Sets list of users that can be resolved.

.PARAMETER groupnet
	Groupnet identifier.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER ignored_trusted_domains
	Includes trusted domains when 'ignore_all_trusts' is set to false.

.PARAMETER ignore_all_trusts
	If set to true, ignores all trusted domains.

.PARAMETER include_trusted_domains
	Includes trusted domains when 'ignore_all_trusts' is set to true.

.PARAMETER instance
	Specifies Active Directory provider instnace.

.PARAMETER kerberos_hdfs_spn
	Determines if connecting through HDFS with Kerberos.

.PARAMETER kerberos_nfs_spn
	Determines if connecting through NFS with Kerberos.

.PARAMETER ldap_sign_and_seal
	Enables encryption and signing on LDAP requests.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER lookup_domains
	Limits user and group lookups to the specified domains.

.PARAMETER lookup_groups
	Looks up AD groups in other providers before allocating a group ID.

.PARAMETER lookup_normalize_groups
	Normalizes AD group names to lowercase before look up.

.PARAMETER lookup_normalize_users
	Normalize AD user names to lowercase before look up.

.PARAMETER lookup_users
	Looks up AD users in other providers before allocating a user ID.

.PARAMETER machine_name
	Specifies name to join AD as.

.PARAMETER machine_password_changes
	Enables periodic changes of the machine password for security.

.PARAMETER machine_password_lifespan
	Sets maximum age of a password in seconds.

.PARAMETER name
	Specifies the Active Directory provider name.

.PARAMETER node_dc_affinity
	Specifies the domain controller for which the node has affinity.

.PARAMETER node_dc_affinity_timeout
	Specifies the timeout for the domain controller for which the local node has affinity.

.PARAMETER nss_enumeration
	Enables the Active Directory provider to respond to 'getpwent' and 'getgrent' requests.

.PARAMETER organizational_unit
	Specifies the organizational unit.

.PARAMETER password
	Specifies the password used during domain join.

.PARAMETER restrict_findable
	Check the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER sfu_support
	Specifies whether to support RFC 2307 attributes on ADS domain controllers.
	Valid inputs: none,rfc2307

.PARAMETER store_sfu_mappings
	Stores SFU mappings permanently in the ID mapper.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER user
	Specifies the user name that has permission to join a machine to the given domain.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$account,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allocate_gids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allocate_uids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$assume_default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$controller_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$dns_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$domain_offline_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$ignored_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$ignore_all_trusts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][array]$include_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$instance,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$kerberos_hdfs_spn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$kerberos_nfs_spn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$ldap_sign_and_seal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$lookup_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$lookup_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$lookup_normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$lookup_normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$lookup_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$machine_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$machine_password_changes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$machine_password_lifespan,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$node_dc_affinity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][int]$node_dc_affinity_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$nss_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$organizational_unit,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][ValidateSet('none','rfc2307')][string]$sfu_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][bool]$store_sfu_mappings,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][array]$unfindable_users,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/auth/providers/ads" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersAdsv3

function New-isiAuthProvidersFile{
<#
.SYNOPSIS
	New Auth Providers File

.DESCRIPTION
	Create a new file provider.

.PARAMETER authentication
	Enables authentication and identity mapping through the authentication provider.

.PARAMETER create_home_directory
	Automatically creates a home directory on the first login.

.PARAMETER enabled
	Enables the file provider.

.PARAMETER enumerate_groups
	Enables the provider to enumerate groups.

.PARAMETER enumerate_users
	Enables the provider to enumerate users.

.PARAMETER findable_groups
	Specifies the list of groups that can be resolved.

.PARAMETER findable_users
	Specifies the list of users that can be resolved.

.PARAMETER group_domain
	Specifies the domain for this provider through which domains are qualified.

.PARAMETER group_file
	Specifies the location of the file that contains information about the group.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER listable_groups
	Specifies the groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies the users that can be viewed in the provider.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER modifiable_groups
	Specifies the groups that can be modified in the provider.

.PARAMETER modifiable_users
	Specifies the users that can be modified in the provider.

.PARAMETER name
	Specifies the name of the file provider.

.PARAMETER netgroup_file
	Specifies the path to a netgroups replacement file.

.PARAMETER normalize_groups
	Normalizes group names to lowercase before look up.

.PARAMETER normalize_users
	Normalizes user names to lowercase before look up.

.PARAMETER ntlm_support
	Specifies which NTLM versions to support for users with NTLM-compatible credentials.
	Valid inputs: all,v2only,none

.PARAMETER password_file
	Specifies the location of the file containing information about users.

.PARAMETER provider_domain
	Specifies the domain for the provider.

.PARAMETER restrict_findable
	If true, checks the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	If true, checks the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER restrict_modifiable
	If true, checks the provider for filtered lists of modifiable and unmodifiable users and groups.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER unmodifiable_groups
	Specifies a group that cannot be modified by the provider.

.PARAMETER unmodifiable_users
	Specifies a user that cannot be modified by the provider.

.PARAMETER user_domain
	Specifies the domain for this provider through which users are qualified.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$group_domain,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$group_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$modifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$modifiable_users,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$netgroup_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$password_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_modifiable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unmodifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unmodifiable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/file" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersFile

function New-isiAuthProvidersKrb5v1{
<#
.SYNOPSIS
	New Auth Providers Krb5

.DESCRIPTION
	Create a new KRB5 provider.

.PARAMETER keytab_entries
	Specifies the key information for the Kerberos SPN.

.PARAMETER keytab_file
	Specifies the path to a keytab file to import.

.PARAMETER manual_keying
	If true, keys are managed manually. If false, keys are managed through kadmin.

.PARAMETER name
	Specifies the Kerberos provider name.

.PARAMETER password
	Specifies the Kerberos provider password.

.PARAMETER realm
	Specifies the name of realm.

.PARAMETER user
	Specifies the name of the user that performs kadmin tasks.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$keytab_entries,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$keytab_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$manual_keying,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$password,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/krb5" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersKrb5v1
Set-Alias New-isiAuthProvidersKrb5 -Value New-isiAuthProvidersKrb5v1
Export-ModuleMember -Alias New-isiAuthProvidersKrb5

function New-isiAuthProvidersKrb5v3{
<#
.SYNOPSIS
	New Auth Providers Krb5

.DESCRIPTION
	Create a new KRB5 provider.

.PARAMETER groupnet
	Groupnet identifier.

.PARAMETER keytab_entries
	Specifies the key information for the Kerberos SPN.

.PARAMETER keytab_file
	Specifies the path to a keytab file to import.

.PARAMETER manual_keying
	If true, keys are managed manually. If false, keys are managed through kadmin.

.PARAMETER name
	Specifies the Kerberos provider name.

.PARAMETER password
	Specifies the Kerberos provider password.

.PARAMETER realm
	Specifies the name of realm.

.PARAMETER user
	Specifies the name of the user that performs kadmin tasks.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$keytab_entries,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$keytab_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$manual_keying,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$password,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/auth/providers/krb5" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersKrb5v3

function New-isiAuthProvidersLdapv1{
<#
.SYNOPSIS
	New Auth Providers Ldap

.DESCRIPTION
	Create a new LDAP provider.

.PARAMETER alternate_security_identities_attribute
	Specifies the attribute name used when searching for alternate security identities.

.PARAMETER authentication
	If true, enables authentication and identity management through the authentication provider.

.PARAMETER balance_servers
	If true, connects the provider to a random server.

.PARAMETER base_dn
	Specifies the root of the tree in which to search identities.

.PARAMETER bind_dn
	Specifies the distinguished name for binding to the LDAP server.

.PARAMETER bind_mechanism
	Specifies which bind mechanism to use when connecting to an LDAP server. The only supported option is the 'simple' value.
	Valid inputs: simple,gssapi,digest-md5

.PARAMETER bind_password
	Specifies the password for the distinguished name for binding to the LDAP server.

.PARAMETER bind_timeout
	Specifies the timeout in seconds when binding to an LDAP server.

.PARAMETER certificate_authority_file
	Specifies the path to the root certificates file.

.PARAMETER check_online_interval
	Specifies the time in seconds between provider online checks.

.PARAMETER cn_attribute
	Specifies the canonical name.

.PARAMETER create_home_directory
	Automatically create the home directory on the first login.

.PARAMETER crypt_password_attribute
	Specifies the hashed password value.

.PARAMETER email_attribute
	Specifies the LDAP Email attribute.

.PARAMETER enabled
	If true, enables the LDAP provider.

.PARAMETER enumerate_groups
	If true, allows the provider to enumerate groups.

.PARAMETER enumerate_users
	If true, allows the provider to enumerate users.

.PARAMETER findable_groups
	Specifies the list of groups that can be resolved.

.PARAMETER findable_users
	Specifies the list of users that can be resolved.

.PARAMETER gecos_attribute
	Specifies the LDAP GECOS attribute.

.PARAMETER gid_attribute
	Specifies the LDAP GID attribute.

.PARAMETER group_base_dn
	Specifies the distinguished name of the entry where LDAP searches for groups are started.

.PARAMETER group_domain
	Specifies the domain for this provider through which groups are qualified.

.PARAMETER group_filter
	Specifies the LDAP filter for group objects.

.PARAMETER group_members_attribute
	Specifies the LDAP Group Members attribute.

.PARAMETER group_search_scope
	Specifies the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER homedir_attribute
	Specifies the LDAP Homedir attribute.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER ignore_tls_errors
	If true, continues over secure connections even if identity checks fail.

.PARAMETER listable_groups
	Specifies the groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies the users that can be viewed in the provider.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER member_of_attribute
	Specifies the LDAP Query Member Of attribute, which performs reverse membership queries.

.PARAMETER name
	Specifies the name of the LDAP provider.

.PARAMETER name_attribute
	Specifies the LDAP UID attribute, which is used as the login name.

.PARAMETER netgroup_base_dn
	Specifies the distinguished name of the entry where LDAP searches for netgroups are started.

.PARAMETER netgroup_filter
	Specifies the LDAP filter for netgroup objects.

.PARAMETER netgroup_members_attribute
	Specifies the LDAP Netgroup Members attribute.

.PARAMETER netgroup_search_scope
	Specifies the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER netgroup_triple_attribute
	Specifies the LDAP Netgroup Triple attribute.

.PARAMETER normalize_groups
	Normalizes group names to lowercase before look up.

.PARAMETER normalize_users
	Normalizes user names to lowercase before look up.

.PARAMETER ntlm_support
	Specifies which NTLM versions to support for users with NTLM-compatible credentials.
	Valid inputs: all,v2only,none

.PARAMETER nt_password_attribute
	Specifies the LDAP NT Password attribute.

.PARAMETER provider_domain
	Specifies the provider domain.

.PARAMETER require_secure_connection
	Determines whether to continue over a non-TLS connection.

.PARAMETER restrict_findable
	If true, checks the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	If true, checks the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER search_scope
	Specifies the default depth from the base DN to perform LDAP searches.
	Valid inputs: base,onelevel,subtree,children

.PARAMETER search_timeout
	Specifies the search timeout period in seconds.

.PARAMETER server_uris
	Specifies the server URIs.

.PARAMETER shell_attribute
	Specifies the the LDAP Shell attribute.

.PARAMETER uid_attribute
	Specifies the the LDAP UID Number attribute.

.PARAMETER unfindable_groups
	Specifies the groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER unique_group_members_attribute
	Sets the LDAP Unique Group Members attribute.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER user_base_dn
	Specifies the distinguished name of the entry at which to start LDAP searches for users.

.PARAMETER user_domain
	Specifies the domain for this provider through which users are qualified.

.PARAMETER user_filter
	Specifies the LDAP filter for user objects.

.PARAMETER user_search_scope
	Specifies the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$alternate_security_identities_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$balance_servers,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$bind_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('simple','gssapi','digest-md5')][string]$bind_mechanism,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$bind_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$bind_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$certificate_authority_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$cn_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$crypt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$email_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$gecos_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$gid_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$group_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$group_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$group_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][ValidateSet('default','base','onelevel','subtree','children')][string]$group_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$homedir_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$ignore_tls_errors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$member_of_attribute,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$name_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$netgroup_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][string]$netgroup_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$netgroup_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][ValidateSet('default','base','onelevel','subtree','children')][string]$netgroup_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][string]$netgroup_triple_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][string]$nt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][bool]$require_secure_connection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][ValidateSet('base','onelevel','subtree','children')][string]$search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=49)][int]$search_timeout,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=50)][array]$server_uris,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=51)][string]$shell_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=52)][string]$uid_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=53)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=54)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=55)][string]$unique_group_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=56)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=57)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=58)][string]$user_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=59)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=60)][string]$user_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=61)][ValidateSet('default','base','onelevel','subtree','children')][string]$user_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=62)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/ldap" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersLdapv1
Set-Alias New-isiAuthProvidersLdap -Value New-isiAuthProvidersLdapv1
Export-ModuleMember -Alias New-isiAuthProvidersLdap

function New-isiAuthProvidersLdapv3{
<#
.SYNOPSIS
	New Auth Providers Ldap

.DESCRIPTION
	Create a new LDAP provider.

.PARAMETER alternate_security_identities_attribute
	Specifies the attribute name used when searching for alternate security identities.

.PARAMETER authentication
	If true, enables authentication and identity management through the authentication provider.

.PARAMETER balance_servers
	If true, connects the provider to a random server.

.PARAMETER base_dn
	Specifies the root of the tree in which to search identities.

.PARAMETER bind_dn
	Specifies the distinguished name for binding to the LDAP server.

.PARAMETER bind_mechanism
	Specifies which bind mechanism to use when connecting to an LDAP server. The only supported option is the 'simple' value.
	Valid inputs: simple,gssapi,digest-md5

.PARAMETER bind_password
	Specifies the password for the distinguished name for binding to the LDAP server.

.PARAMETER bind_timeout
	Specifies the timeout in seconds when binding to an LDAP server.

.PARAMETER certificate_authority_file
	Specifies the path to the root certificates file.

.PARAMETER check_online_interval
	Specifies the time in seconds between provider online checks.

.PARAMETER cn_attribute
	Specifies the canonical name.

.PARAMETER create_home_directory
	Automatically create the home directory on the first login.

.PARAMETER crypt_password_attribute
	Specifies the hashed password value.

.PARAMETER email_attribute
	Specifies the LDAP Email attribute.

.PARAMETER enabled
	If true, enables the LDAP provider.

.PARAMETER enumerate_groups
	If true, allows the provider to enumerate groups.

.PARAMETER enumerate_users
	If true, allows the provider to enumerate users.

.PARAMETER findable_groups
	Specifies the list of groups that can be resolved.

.PARAMETER findable_users
	Specifies the list of users that can be resolved.

.PARAMETER gecos_attribute
	Specifies the LDAP GECOS attribute.

.PARAMETER gid_attribute
	Specifies the LDAP GID attribute.

.PARAMETER groupnet
	Groupnet identifier.

.PARAMETER group_base_dn
	Specifies the distinguished name of the entry where LDAP searches for groups are started.

.PARAMETER group_domain
	Specifies the domain for this provider through which groups are qualified.

.PARAMETER group_filter
	Specifies the LDAP filter for group objects.

.PARAMETER group_members_attribute
	Specifies the LDAP Group Members attribute.

.PARAMETER group_search_scope
	Specifies the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER homedir_attribute
	Specifies the LDAP Homedir attribute.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER ignore_tls_errors
	If true, continues over secure connections even if identity checks fail.

.PARAMETER listable_groups
	Specifies the groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies the users that can be viewed in the provider.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER member_of_attribute
	Specifies the LDAP Query Member Of attribute, which performs reverse membership queries.

.PARAMETER name
	Specifies the name of the LDAP provider.

.PARAMETER name_attribute
	Specifies the LDAP UID attribute, which is used as the login name.

.PARAMETER netgroup_base_dn
	Specifies the distinguished name of the entry where LDAP searches for netgroups are started.

.PARAMETER netgroup_filter
	Specifies the LDAP filter for netgroup objects.

.PARAMETER netgroup_members_attribute
	Specifies the LDAP Netgroup Members attribute.

.PARAMETER netgroup_search_scope
	Specifies the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER netgroup_triple_attribute
	Specifies the LDAP Netgroup Triple attribute.

.PARAMETER normalize_groups
	Normalizes group names to lowercase before look up.

.PARAMETER normalize_users
	Normalizes user names to lowercase before look up.

.PARAMETER ntlm_support
	Specifies which NTLM versions to support for users with NTLM-compatible credentials.
	Valid inputs: all,v2only,none

.PARAMETER nt_password_attribute
	Specifies the LDAP NT Password attribute.

.PARAMETER provider_domain
	Specifies the provider domain.

.PARAMETER require_secure_connection
	Determines whether to continue over a non-TLS connection.

.PARAMETER restrict_findable
	If true, checks the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	If true, checks the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER search_scope
	Specifies the default depth from the base DN to perform LDAP searches.
	Valid inputs: base,onelevel,subtree,children

.PARAMETER search_timeout
	Specifies the search timeout period in seconds.

.PARAMETER server_uris
	Specifies the server URIs.

.PARAMETER shell_attribute
	Specifies the the LDAP Shell attribute.

.PARAMETER uid_attribute
	Specifies the the LDAP UID Number attribute.

.PARAMETER unfindable_groups
	Specifies the groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER unique_group_members_attribute
	Sets the LDAP Unique Group Members attribute.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER user_base_dn
	Specifies the distinguished name of the entry at which to start LDAP searches for users.

.PARAMETER user_domain
	Specifies the domain for this provider through which users are qualified.

.PARAMETER user_filter
	Specifies the LDAP filter for user objects.

.PARAMETER user_search_scope
	Specifies the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$alternate_security_identities_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$balance_servers,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$bind_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('simple','gssapi','digest-md5')][string]$bind_mechanism,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$bind_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$bind_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$certificate_authority_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$cn_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$crypt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$email_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$gecos_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$gid_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$group_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$group_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][string]$group_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][ValidateSet('default','base','onelevel','subtree','children')][string]$group_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$homedir_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$ignore_tls_errors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$member_of_attribute,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$name_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][string]$netgroup_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$netgroup_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$netgroup_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateSet('default','base','onelevel','subtree','children')][string]$netgroup_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][string]$netgroup_triple_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][string]$nt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][bool]$require_secure_connection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=49)][ValidateSet('base','onelevel','subtree','children')][string]$search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=50)][int]$search_timeout,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=51)][array]$server_uris,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=52)][string]$shell_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=53)][string]$uid_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=54)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=55)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=56)][string]$unique_group_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=57)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=58)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=59)][string]$user_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=60)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=61)][string]$user_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=62)][ValidateSet('default','base','onelevel','subtree','children')][string]$user_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=63)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/auth/providers/ldap" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersLdapv3

function New-isiAuthProvidersNisv1{
<#
.SYNOPSIS
	New Auth Providers Nis

.DESCRIPTION
	Create a new NIS provider.

.PARAMETER authentication
	If true, enables authentication and identity management through the authentication provider.

.PARAMETER balance_servers
	If true, connects the provider to a random server.

.PARAMETER check_online_interval
	Specifies the time in seconds between provider online checks.

.PARAMETER create_home_directory
	Automatically creates the home directory on the first login.

.PARAMETER enabled
	If true, enables the NIS provider.

.PARAMETER enumerate_groups
	If true, allows the provider to enumerate groups.

.PARAMETER enumerate_users
	If true, allows the provider to enumerate users.

.PARAMETER findable_groups
	Specifies the list of groups that can be resolved.

.PARAMETER findable_users
	Specifies the list of users that can be resolved.

.PARAMETER group_domain
	Specifies the domain for this provider through which groups are qualified.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER hostname_lookup
	If true, enables host name look ups.

.PARAMETER listable_groups
	Specifies the groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies the users that can be viewed in the provider.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER name
	Specifies the NIS provider name.

.PARAMETER nis_domain
	Specifies the NIS domain name.

.PARAMETER normalize_groups
	Normalizes group names to lowercase before look up.

.PARAMETER normalize_users
	Normalizes user names to lowercase before look up.

.PARAMETER ntlm_support
	Specifies which NTLM versions to support for users with NTLM-compatible credentials.
	Valid inputs: all,v2only,none

.PARAMETER provider_domain
	Specifies the domain for the provider.

.PARAMETER request_timeout
	Specifies the request timeout interval in seconds.

.PARAMETER restrict_findable
	If true, checks the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	If true, checks the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER retry_time
	Specifies the timeout period in seconds after which a request will be retried.

.PARAMETER servers
	Adds an NIS server for this provider.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER user_domain
	Specifies the domain for this provider through which users are qualified.

.PARAMETER ypmatch_using_tcp
	If true, specifies TCP for YP Match operations.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$hostname_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$login_shell,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$nis_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$request_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$retry_time,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][array]$servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$ypmatch_using_tcp,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/nis" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersNisv1
Set-Alias New-isiAuthProvidersNis -Value New-isiAuthProvidersNisv1
Export-ModuleMember -Alias New-isiAuthProvidersNis

function New-isiAuthProvidersNisv3{
<#
.SYNOPSIS
	New Auth Providers Nis

.DESCRIPTION
	Create a new NIS provider.

.PARAMETER authentication
	If true, enables authentication and identity management through the authentication provider.

.PARAMETER balance_servers
	If true, connects the provider to a random server.

.PARAMETER check_online_interval
	Specifies the time in seconds between provider online checks.

.PARAMETER create_home_directory
	Automatically creates the home directory on the first login.

.PARAMETER enabled
	If true, enables the NIS provider.

.PARAMETER enumerate_groups
	If true, allows the provider to enumerate groups.

.PARAMETER enumerate_users
	If true, allows the provider to enumerate users.

.PARAMETER findable_groups
	Specifies the list of groups that can be resolved.

.PARAMETER findable_users
	Specifies the list of users that can be resolved.

.PARAMETER groupnet
	Groupnet identifier.

.PARAMETER group_domain
	Specifies the domain for this provider through which groups are qualified.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER hostname_lookup
	If true, enables host name look ups.

.PARAMETER listable_groups
	Specifies the groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies the users that can be viewed in the provider.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER name
	Specifies the NIS provider name.

.PARAMETER nis_domain
	Specifies the NIS domain name.

.PARAMETER normalize_groups
	Normalizes group names to lowercase before look up.

.PARAMETER normalize_users
	Normalizes user names to lowercase before look up.

.PARAMETER ntlm_support
	Specifies which NTLM versions to support for users with NTLM-compatible credentials.
	Valid inputs: all,v2only,none

.PARAMETER provider_domain
	Specifies the domain for the provider.

.PARAMETER request_timeout
	Specifies the request timeout interval in seconds.

.PARAMETER restrict_findable
	If true, checks the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	If true, checks the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER retry_time
	Specifies the timeout period in seconds after which a request will be retried.

.PARAMETER servers
	Adds an NIS server for this provider.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER user_domain
	Specifies the domain for this provider through which users are qualified.

.PARAMETER ypmatch_using_tcp
	If true, specifies TCP for YP Match operations.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$hostname_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$login_shell,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$nis_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$request_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$retry_time,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][bool]$ypmatch_using_tcp,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/auth/providers/nis" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersNisv3

function New-isiAuthRefresh{
<#
.SYNOPSIS
	New Auth Refresh

.DESCRIPTION
	Refresh the authentication service configuration.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/auth/refresh" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthRefresh

function New-isiAuthRoles{
<#
.SYNOPSIS
	New Auth Roles

.DESCRIPTION
	Create a new role.

.PARAMETER description
	Specifies the description of the role.

.PARAMETER members
	Specifies the users or groups that have this role.

.PARAMETER name
	Specifies the name of the role.

.PARAMETER privileges
	Specifies the privileges granted by this role.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$members,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$privileges,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/roles" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthRoles

function New-isiAuthRoleMembers{
<#
.SYNOPSIS
	New Auth Role Members

.DESCRIPTION
	Add a member to the role.

.PARAMETER role_id
	Role role_id

.PARAMETER role_name
	Role role_name

.PARAMETER id
	Specifies the serialized form of a persona, which can be 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', or 'SID:S-1-1'.

.PARAMETER name
	Specifies the persona name, which must be combined with a type.

.PARAMETER type
	Specifies the type of persona, which must be combined with a name.
	Valid inputs: user,group,wellknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$role_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$role_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('user','group','wellknown')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
				$BoundParameters.Remove('role_id') | out-null
			} else {
				$parameter1 = $role_name
				$BoundParameters.Remove('role_name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/roles/$parameter1/members" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthRoleMembers

function New-isiAuthRolePrivileges{
<#
.SYNOPSIS
	New Auth Role Privileges

.DESCRIPTION
	Add a privilege to the role.

.PARAMETER role_id
	Role role_id

.PARAMETER role_name
	Role role_name

.PARAMETER id
	Specifies the ID of the privilege.

.PARAMETER name
	Specifies the name of the privilege.

.PARAMETER read_only
	True, if the privilege is read-only.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$role_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$role_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
				$BoundParameters.Remove('role_id') | out-null
			} else {
				$parameter1 = $role_name
				$BoundParameters.Remove('role_name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/roles/$parameter1/privileges" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthRolePrivileges

function New-isiAuthSettingsKrb5Domains{
<#
.SYNOPSIS
	New Auth Settings Krb5 Domains

.DESCRIPTION
	Create a new krb5 domain.

.PARAMETER domain
	Specifies the name of the domain.

.PARAMETER realm
	Specifies the name of the realm.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$domain,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/settings/krb5/domains" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.domain
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthSettingsKrb5Domains

function New-isiAuthSettingsKrb5Realms{
<#
.SYNOPSIS
	New Auth Settings Krb5 Realms

.DESCRIPTION
	Create a new krb5 realm.

.PARAMETER admin_server
	Specifies the administrative server hostname.

.PARAMETER default_domain
	Specifies the default domain mapped to the realm.

.PARAMETER is_default_realm
	If true, indicates that the realm is the default.

.PARAMETER kdc
	Specifies the list of KDC hostnames.

.PARAMETER realm
	Specifies the name of the realm.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$admin_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$is_default_realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$kdc,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/settings/krb5/realms" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthSettingsKrb5Realms

function New-isiAuthUsers{
<#
.SYNOPSIS
	New Auth Users

.DESCRIPTION
	Create a new user.

.PARAMETER email
	Specifies an email address for the user.

.PARAMETER enabled
	If true, the authenticated user is enabled.

.PARAMETER expiry
	Specifies the Unix Epoch time when the auth user will expire.

.PARAMETER gecos
	Specifies the GECOS value, which is usually the full name.

.PARAMETER home_directory
	Specifies a home directory for the user.

.PARAMETER name
	Specifies a user name.

.PARAMETER password
	Changes the password for the user.

.PARAMETER password_expires
	If true, the password should expire.

.PARAMETER primary_group
	Specifies the primary group by name.

.PARAMETER prompt_password_change
	If true, prompts the user to change their password at the next login.

.PARAMETER shell
	Specifies the shell for the user.

.PARAMETER sid
	Specifies a security identifier.

.PARAMETER uid
	Specifies a numeric user identifier.

.PARAMETER unlock
	If true, the user account should be unlocked.

.PARAMETER provider
	Optional provider type.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$gecos,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$home_directory,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$password_expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$primary_group,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$prompt_password_change,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$sid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$unlock,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters.Remove('provider') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/users" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthUsers

function New-isiAuthUserMemberOfGroupsv3{
<#
.SYNOPSIS
	New Auth User Member Of Groups

.DESCRIPTION
	Add the user to a group.

.PARAMETER user_id
	User user_id

.PARAMETER user_name
	User user_name

.PARAMETER id
	Specifies the serialized form of a persona, which can be 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', or 'SID:S-1-1'.

.PARAMETER name
	Specifies the persona name, which must be combined with a type.

.PARAMETER type
	Specifies the type of persona, which must be combined with a name.
	Valid inputs: user,group,wellknown

.PARAMETER provider
	Filter groups by provider.

.PARAMETER access_zone
	Filter groups by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$user_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$user_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('user','group','wellknown')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
				$BoundParameters.Remove('user_id') | out-null
			} else {
				$parameter1 = $user_name
				$BoundParameters.Remove('user_name') | out-null
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters.Remove('provider') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/auth/users/$parameter1/member-of" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthUserMemberOfGroupsv3

function New-isiAuthUserMemberOfGroupsv1{
<#
.SYNOPSIS
	New Auth User Member Of Groups

.DESCRIPTION
	Add the user to a group.

.PARAMETER user_id
	User user_id

.PARAMETER user_name
	User user_name

.PARAMETER id
	Specifies the serialized form of a persona, which can be 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', or 'SID:S-1-1'.

.PARAMETER name
	Specifies the persona name, which must be combined with a type.

.PARAMETER type
	Specifies the type of persona, which must be combined with a name.
	Valid inputs: user,group,wellknown

.PARAMETER provider
	Filter groups by provider.

.PARAMETER access_zone
	Filter groups by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$user_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$user_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('user','group','wellknown')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
				$BoundParameters.Remove('user_id') | out-null
			} else {
				$parameter1 = $user_name
				$BoundParameters.Remove('user_name') | out-null
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters.Remove('provider') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/users/$parameter1/member_of" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthUserMemberOfGroupsv1

function New-isiCloudAccess{
<#
.SYNOPSIS
	New Cloud Access

.DESCRIPTION
	Add a cluster identifier to access list.

.PARAMETER guid
	A cluster guid indicating the birth place of one or more accounts or policies on this cluster

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$guid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cloud/access" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudAccess

function New-isiCloudAccountsv3{
<#
.SYNOPSIS
	New Cloud Accounts

.DESCRIPTION
	Create a new account.

.PARAMETER account_id
	(S3 only) The user id of the S3 account

.PARAMETER account_username
	The username required to authenticate against the cloud service

.PARAMETER birth_cluster_id
	The guid of the cluster where this account was created

.PARAMETER enabled
	Whether this account is explicitly enabled or disabled by a user

.PARAMETER key
	A valid authentication key for connecting to the cloud

.PARAMETER name
	A unique name for this account

.PARAMETER skip_ssl_validation
	Indicates whether to skip SSL certificate validation when connecting to the cloud

.PARAMETER storage_region
	(S3 only) An appropriate region for the S3 account.  For example, faster access times may be gained by referencing a nearby region

.PARAMETER telemetry_bucket
	(S3 only) The name of the bucket into which generated metrics reports are placed by the cloud service provider

.PARAMETER type
	The type of cloud protocol required.  E.g., "isilon" for EMC Isilon, "ecs" for EMC ECS Appliance, "ecs2" for EMC Elastic Cloud Storage Service, "azure" for Microsoft Azure and "s3" for Amazon S3
	Valid inputs: isilon,ecs,ecs2,azure,s3,ran

.PARAMETER uri
	A valid URI pointing to the location of the cloud storage

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$account_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$account_username,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$birth_cluster_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$enabled,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$key,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$skip_ssl_validation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$storage_region,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$telemetry_bucket,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('isilon','ecs','ecs2','azure','s3','ran')][string]$type,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$uri,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cloud/accounts" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudAccountsv3

function New-isiCloudJobsv3{
<#
.SYNOPSIS
	New Cloud Jobs

.DESCRIPTION
	Create a new job.

.PARAMETER accounts
	The names of accounts for COI restore

.PARAMETER directories
	Directories addressed by this job

.PARAMETER expiration_date
	The new expiration date in seconds

.PARAMETER files
	Filenames addressed by this job

.PARAMETER file_matching_pattern
	The file filtering logic to find files for this job. (Only applicable for 'recall' jobs)

.PARAMETER policy
	The name of an existing cloudpool policy to apply to this job. (Only applicable for 'archive' jobs)

.PARAMETER type
	The type of cloud action to be performed by this job.
	Valid inputs: archive,recall,local-garbage-collection,cloud-garbage-collection,cache-writeback,cache-on-access,cache-invalidation,restore-coi

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$accounts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$expiration_date,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$policy,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('archive','recall','local-garbage-collection','cloud-garbage-collection','cache-writeback','cache-on-access','cache-invalidation','restore-coi')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cloud/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudJobsv3

function New-isiCloudPoolsv3{
<#
.SYNOPSIS
	New Cloud Pools

.DESCRIPTION
	Create a new pool.

.PARAMETER accounts
	A list of valid names for the accounts in this pool.  There is currently only one account allowed per pool.

.PARAMETER birth_cluster_id
	The guid of the cluster where this pool was created

.PARAMETER description
	A brief description of this pool

.PARAMETER name
	A unique name for this pool

.PARAMETER type
	The type of cloud protocol required.  E.g., "isilon" for EMC Isilon, "ecs" for EMC ECS Appliance, "ecs2" for EMC Elastic Cloud Storage Service, "azure" for Microsoft Azure and "s3" for Amazon S3
	Valid inputs: isilon,ecs,ecs2,azure,s3,ran

.PARAMETER vendor
	A string identifier of the cloud services vendor

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$accounts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$birth_cluster_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$description,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('isilon','ecs','ecs2','azure','s3','ran')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$vendor,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cloud/pools" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudPoolsv3

function New-isiCloudSettingsEncryptionKey{
<#
.SYNOPSIS
	New Cloud Settings Encryption Key

.DESCRIPTION
	Regenerate master encryption key.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cloud/settings/encryption-key" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudSettingsEncryptionKey

function New-isiCloudSettingsReportingEula{
<#
.SYNOPSIS
	New Cloud Settings Reporting Eula

.DESCRIPTION
	Accept telemetry collection EULA.

.PARAMETER accepted
	Indicates whether the telemetry collection warning has been acknowledged

.PARAMETER body
	The body of the telemetry collection warning

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$accepted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$body,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cloud/settings/reporting-eula" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudSettingsReportingEula

function New-isiClusterAddNode{
<#
.SYNOPSIS
	New Cluster Add Node

.DESCRIPTION
	Serial number and arguments of node to add.

.PARAMETER allow_down
	Allow down nodes (Default false).

.PARAMETER serial_number
	Serial number of this node.

.PARAMETER skip_hardware_version_check
	Bypass hardware version checks (Default false).

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$allow_down,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$serial_number,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$skip_hardware_version_check,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/add-node" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterAddNode

function New-isiClusterNodeDriveAdd{
<#
.SYNOPSIS
	New Cluster Node Drive Add

.DESCRIPTION
	Add a drive to a node.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDriveAdd

function New-isiClusterNodeDriveFirmwareUpdate{
<#
.SYNOPSIS
	New Cluster Node Drive Firmware Update

.DESCRIPTION
	Start a drive firmware update.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER cluster_wide
	Indicates whether this is a cluster wide drive firwmare update or not

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$cluster_wide,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDriveFirmwareUpdate

function New-isiClusterNodeDriveFormat{
<#
.SYNOPSIS
	New Cluster Node Drive Format

.DESCRIPTION
	Format a drive for use by OneFS.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER purpose
	The purpose to which this drive should be formatted. If not specified, defaults to 'None', which will be automatically purposed based on node configuration and drive type.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$purpose,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDriveFormat

function New-isiClusterNodeDrivePurpose{
<#
.SYNOPSIS
	New Cluster Node Drive Purpose

.DESCRIPTION
	Assign a drive to a specific use case.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER purpose
	The purpose to which this drive should be assigned. This field is required for the 'purpose' action.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$purpose,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDrivePurpose

function New-isiClusterNodeDriveSmartfail{
<#
.SYNOPSIS
	New Cluster Node Drive Smartfail

.DESCRIPTION
	Remove a drive from use by OneFS.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDriveSmartfail

function New-isiClusterNodeDriveStopfail{
<#
.SYNOPSIS
	New Cluster Node Drive Stopfail

.DESCRIPTION
	Stop restriping from a smartfailing drive.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDriveStopfail

function New-isiClusterNodeDriveSuspend{
<#
.SYNOPSIS
	New Cluster Node Drive Suspend

.DESCRIPTION
	Temporarily remove a drive from use by OneFS.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER driveidid2
	 driveidid2

.PARAMETER driveidname2
	 driveidname2

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$driveidid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$driveidname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
				$BoundParameters.Remove('driveidid2') | out-null
			} else {
				$parameter2 = $driveidname2
				$BoundParameters.Remove('driveidname2') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeDriveSuspend

function New-isiClusterNodeReboot{
<#
.SYNOPSIS
	New Cluster Node Reboot

.DESCRIPTION
	Reboot the node specified by <LNN>.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/reboot" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeReboot

function New-isiClusterNodeShutdown{
<#
.SYNOPSIS
	New Cluster Node Shutdown

.DESCRIPTION
	Shutdown the node specified by <LNN>.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/cluster/nodes/$parameter1/shutdown" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiClusterNodeShutdown

function New-isiEventAlertConditions{
<#
.SYNOPSIS
	New Event Alert Conditions

.DESCRIPTION
	Create a new alert condition.

.PARAMETER categories
	Event Group categories to be alerted

.PARAMETER channel_ids
	Channels for alert

.PARAMETER condition
	Trigger condition for alert
	Valid inputs: NEW,NEW EVENTS,ONGOING,SEVERITY INCREASE,SEVERITY DECREASE,RESOLVED

.PARAMETER eventgroup_ids
	Event Group IDs to be alerted

.PARAMETER id
	Unique identifier.

.PARAMETER interval
	Required with ONGOING condition only, period in seconds between alerts of ongoing conditions

.PARAMETER limit
	Required with NEW EVENTS condition only, limits the number of alerts sent as events are added

.PARAMETER name
	Unique identifier.

.PARAMETER transient
	Any eventgroup lasting less than this many seconds is deemed transient and will not generate alerts under this condition.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$categories,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$channel_ids,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('NEW','NEW EVENTS','ONGOING','SEVERITY INCREASE','SEVERITY DECREASE','RESOLVED')][string]$condition,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$eventgroup_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$limit,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$transient,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/event/alert-conditions" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiEventAlertConditions

function New-isiEventChannels{
<#
.SYNOPSIS
	New Event Channels

.DESCRIPTION
	Create a new channel.

.PARAMETER allowed_nodes
	Nodes that can be masters for this channel

.PARAMETER enabled
	Channel is to be used or not

.PARAMETER excluded_nodes
	Nodes that can be masters for this channel

.PARAMETER id
	Unique identifier.

.PARAMETER name
	Channel name,  may not contain /, max length 254.

.PARAMETER parameters
	A collection of parameters dependent on the channel type

.PARAMETER system
	Channel is a pre-defined system channel

.PARAMETER type
	The mechanism used by the channel
	Valid inputs: connectemc,smtp,snmp

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$allowed_nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$excluded_nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$parameters,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$system,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('connectemc','smtp','snmp')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/event/channels" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiEventChannels

function New-isiEventEventsv3{
<#
.SYNOPSIS
	New Event Events

.DESCRIPTION
	Create a test event.

.PARAMETER message
	Message for test event

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$message,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/event/events" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiEventEventsv3

function New-isiFilepoolPolicies{
<#
.SYNOPSIS
	New Filepool Policies

.DESCRIPTION
	Create a new policy.

.PARAMETER actions
	A list of actions to be taken for matching files

.PARAMETER apply_order
	The order in which this policy should be applied (relative to other policies)

.PARAMETER description
	A description for this policy

.PARAMETER file_matching_pattern
	The file matching rules for this policy

.PARAMETER name
	A unique name for this policy

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$actions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$apply_order,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$description,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$file_matching_pattern,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/filepool/policies" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiFilepoolPolicies

function New-isiHardeningApply{
<#
.SYNOPSIS
	New Hardening Apply

.DESCRIPTION
	Apply hardening on the cluster.

.PARAMETER profile
	Hardening profile.

.PARAMETER report
	Option to only generate and display a report on current cluster configuration with respect to the expected configuation required to apply hardening. If his option is set to true, hardening is not applied after the report is displayed. By default, this option is false.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$profile,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$report,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/hardening/apply" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.message
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHardeningApply

function New-isiHardeningResolve{
<#
.SYNOPSIS
	New Hardening Resolve

.DESCRIPTION
	Resolve issues related to hardening, found in current cluster configuration.

.PARAMETER profile
	Hardening profile.

.PARAMETER accept
	If true, execution proceeds to resolve all issues. If false, executrion aborts. This is a required argument.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$profile,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$accept,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($accept){
				$queryArguments += 'accept=' + $accept
				$BoundParameters.Remove('accept') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/hardening/resolve" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.message
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHardeningResolve

function New-isiHardeningRevert{
<#
.SYNOPSIS
	New Hardening Revert

.DESCRIPTION
	Revert hardening on the cluster.

.PARAMETER enforce
	If specified, revert operation continues even in case of a failure. Default is false in which case revert stops at the first failure.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
				$BoundParameters.Remove('enforce') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/hardening/revert" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.message
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHardeningRevert

function New-isiHardwareTape{
<#
.SYNOPSIS
	New Hardware Tape

.DESCRIPTION
	Tape/Changer devices rescan

.PARAMETER id
	Name id

.PARAMETER name
	Name name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/hardware/tape/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHardwareTape

function New-isiJobsv1{
<#
.SYNOPSIS
	New Jobs

.DESCRIPTION
	Queue a new instance of a job type.

.PARAMETER allow_dup
	Whether or not to queue the job if one of the same type is already running or queued.

.PARAMETER changelistcreate_params
	Parameters required for the ChangelistCreate job.

.PARAMETER domainmark_params
	Parameters required for the DomainMark job.

.PARAMETER paths
	For jobs which take paths, the IFS paths to pass to the job.

.PARAMETER policy
	Impact policy of this job instance.

.PARAMETER prepair_params
	Parameters required for the PermissionRepair job.

.PARAMETER priority
	Priority of this job instance; lower numbers preempt higher numbers.

.PARAMETER smartpoolstree_params
	Optional parameters for the SmartPoolsTree job.

.PARAMETER snaprevert_params
	Parameters required for the SnapRevert job.

.PARAMETER type
	Job type to queue.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$allow_dup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$changelistcreate_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$domainmark_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$prepair_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][object]$smartpoolstree_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$snaprevert_params,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/job/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiJobsv1
Set-Alias New-isiJobs -Value New-isiJobsv1
Export-ModuleMember -Alias New-isiJobs

function New-isiJobsv3{
<#
.SYNOPSIS
	New Job Jobs

.DESCRIPTION
	Queue a new instance of a job type.

.PARAMETER allow_dup
	Whether or not to queue the job if one of the same type is already running or queued.

.PARAMETER avscan_params
	Parameters required for the AVScan job.

.PARAMETER changelistcreate_params
	Parameters required for the ChangelistCreate job.

.PARAMETER domainmark_params
	Parameters required for the DomainMark job.

.PARAMETER paths
	For jobs which take paths, the IFS paths to pass to the job.

.PARAMETER policy
	Impact policy of this job instance.

.PARAMETER prepair_params
	Parameters required for the PermissionRepair job.

.PARAMETER priority
	Priority of this job instance; lower numbers preempt higher numbers.

.PARAMETER smartpoolstree_params
	Optional parameters for the SmartPoolsTree job.

.PARAMETER snaprevert_params
	Parameters required for the SnapRevert job.

.PARAMETER type
	Job type to queue.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$allow_dup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$avscan_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$changelistcreate_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$domainmark_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$prepair_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$smartpoolstree_params,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][object]$snaprevert_params,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/job/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiJobsv3

function New-isiJobPolicies{
<#
.SYNOPSIS
	New Job Policies

.DESCRIPTION
	Create a new job impact policy.

.PARAMETER description
	A helpful human-readable description of the impact policy.

.PARAMETER intervals
	

.PARAMETER name
	The name of the impact policy.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$intervals,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/job/policies" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiJobPolicies

function New-isiLicenses{
<#
.SYNOPSIS
	New Licenses

.DESCRIPTION
	Install a new license key.

.PARAMETER key
	New license key.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/license/licenses" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiLicenses

function New-isiNetworkDnscacheFlush{
<#
.SYNOPSIS
	New Network Dnscache Flush

.DESCRIPTION
	Flush the DNSCache.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/network/dnscache/flush" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNetworkDnscacheFlush

function New-isiNetworkGroupnets{
<#
.SYNOPSIS
	New Network Groupnets

.DESCRIPTION
	Create a new groupnet.

.PARAMETER description
	A description of the groupnet.

.PARAMETER dns_cache_enabled
	DNS caching is enabled or disabled.

.PARAMETER dns_options
	List of DNS resolver options.

.PARAMETER dns_search
	List of DNS search suffixes.

.PARAMETER dns_servers
	List of Domain Name Server IP addresses.

.PARAMETER name
	The name of the groupnet.

.PARAMETER server_side_dns_search
	Enable or disable appending nodes DNS search  list to client DNS inquiries directed at SmartConnect service IP.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$dns_cache_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$dns_options,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$dns_search,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$dns_servers,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$server_side_dns_search,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/network/groupnets" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNetworkGroupnets

function New-isiNetworkGroupnetSubnets{
<#
.SYNOPSIS
	New Network Groupnet Subnets

.DESCRIPTION
	Create a new subnet.

.PARAMETER id
	Groupnet id

.PARAMETER addr_family
	IP address format.
	Valid inputs: ipv4,ipv6

.PARAMETER description
	A description of the subnet.

.PARAMETER dsr_addrs
	List of Direct Server Return addresses.

.PARAMETER gateway
	Gateway IP address.

.PARAMETER gateway_priority
	Gateway priority.

.PARAMETER mtu
	MTU of the subnet.

.PARAMETER name
	The name of the subnet.

.PARAMETER prefixlen
	Subnet Prefix Length.

.PARAMETER sc_service_addr
	The address that SmartConnect listens for DNS requests.

.PARAMETER vlan_enabled
	VLAN tagging enabled or disabled.

.PARAMETER vlan_id
	VLAN ID for all interfaces in the subnet.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('ipv4','ipv6')][string]$addr_family,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$dsr_addrs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$gateway,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$gateway_priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$mtu,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$prefixlen,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$sc_service_addr,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$vlan_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$vlan_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$parameter1 = $id
			$BoundParameters.Remove('id') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/network/groupnets/$parameter1/subnets" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNetworkGroupnetSubnets

function New-isiNetworkGroupnetSubnetPools{
<#
.SYNOPSIS
	New Network Groupnet Subnet Pools

.DESCRIPTION
	Create a new pool.

.PARAMETER groupnet_id
	Groupnet groupnet_id

.PARAMETER groupnet_name
	Groupnet groupnet_name

.PARAMETER id
	 id

.PARAMETER access_zone
	Name of a valid access zone to map IP address pool to the zone.

.PARAMETER aggregation_mode
	OneFS supports the following NIC aggregation modes.
	Valid inputs: roundrobin,failover,lacp,fec

.PARAMETER alloc_method
	Specifies how IP address allocation is done among pool members.
	Valid inputs: dynamic,static

.PARAMETER description
	A description of the pool.

.PARAMETER ifaces
	List of interface members in this pool.

.PARAMETER name
	The name of the pool. It must be unique throughout the given subnet.It's a required field with POST method.

.PARAMETER ranges
	List of IP address ranges in this pool.

.PARAMETER rebalance_policy
	Rebalance policy..
	Valid inputs: auto,manual

.PARAMETER sc_auto_unsuspend_delay
	Time delay in seconds before a node which has been                 automatically unsuspended becomes usable in SmartConnect                responses for pool zones.

.PARAMETER sc_connect_policy
	SmartConnect client connection balancing policy.
	Valid inputs: round_robin,conn_count,throughput,cpu_usage

.PARAMETER sc_dns_zone
	SmartConnect zone name for the pool.

.PARAMETER sc_dns_zone_aliases
	List of SmartConnect zone aliases (DNS names) to the pool.

.PARAMETER sc_failover_policy
	SmartConnect IP failover policy.
	Valid inputs: round_robin,conn_count,throughput,cpu_usage

.PARAMETER sc_subnet
	Name of SmartConnect service subnet for this pool.

.PARAMETER sc_ttl
	Time to live value for SmartConnect DNS query responses in seconds.

.PARAMETER static_routes
	List of interface members in this pool.

.PARAMETER enforce
	force creating this pool even if it causes an MTU conflict.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$groupnet_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$groupnet_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('roundrobin','failover','lacp','fec')][string]$aggregation_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('dynamic','static')][string]$alloc_method,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$ifaces,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][array]$ranges,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('auto','manual')][string]$rebalance_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$sc_auto_unsuspend_delay,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateSet('round_robin','conn_count','throughput','cpu_usage')][string]$sc_connect_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$sc_dns_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$sc_dns_zone_aliases,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateSet('round_robin','conn_count','throughput','cpu_usage')][string]$sc_failover_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$sc_subnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$sc_ttl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$static_routes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('groupnet_id')){
				$parameter1 = $groupnet_id
				$BoundParameters.Remove('groupnet_id') | out-null
			} else {
				$parameter1 = $groupnet_name
				$BoundParameters.Remove('groupnet_name') | out-null
			}
			$parameter2 = $id
			$BoundParameters.Remove('id') | out-null
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
				$BoundParameters.Remove('enforce') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/network/groupnets/$parameter1/subnets/$parameter2" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNetworkGroupnetSubnetPools

function New-isiNetworkScRebalanceAll{
<#
.SYNOPSIS
	New Network Sc Rebalance All

.DESCRIPTION
	Rebalance IP addresses in all pools.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/network/sc-rebalance-all" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNetworkScRebalanceAll

function New-isiHdfsProxyUsers{
<#
.SYNOPSIS
	New Hdfs Proxyusers

.DESCRIPTION
	Create a new HDFS proxyuser.

.PARAMETER id
	The ID of the role.

.PARAMETER members
	Users or groups impersonated by proxyuser.

.PARAMETER name
	The name of the proxyuser.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$members,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/protocols/hdfs/proxyusers" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHdfsProxyUsers

function New-isiHdfsProxyUserMembers{
<#
.SYNOPSIS
	New Hdfs Proxyuser Members

.DESCRIPTION
	Add a member to the HDFS proxyuser.

.PARAMETER proxyuser_id
	Proxyuser proxyuser_id

.PARAMETER proxyuser_name
	Proxyuser proxyuser_name

.PARAMETER id
	Specifies the serialized form of a persona, which can be 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', or 'SID:S-1-1'.

.PARAMETER name
	Specifies the persona name, which must be combined with a type.

.PARAMETER type
	Specifies the type of persona, which must be combined with a name.
	Valid inputs: user,group,wellknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$proxyuser_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$proxyuser_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('user','group','wellknown')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('proxyuser_id')){
				$parameter1 = $proxyuser_id
				$BoundParameters.Remove('proxyuser_id') | out-null
			} else {
				$parameter1 = $proxyuser_name
				$BoundParameters.Remove('proxyuser_name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1/members" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHdfsProxyUserMembers

function New-isiHdfsRacks{
<#
.SYNOPSIS
	New Hdfs Racks

.DESCRIPTION
	Create a new HDFS rack.

.PARAMETER client_ip_ranges
	Array of IP ranges. Clients from one of these IP ranges are served by corresponding nodes from ip_pools array.

.PARAMETER ip_pools
	Array of IP pool names to use for serving clients from client_ip_ranges.

.PARAMETER name
	Name of the rack

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$client_ip_ranges,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$ip_pools,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/protocols/hdfs/racks" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHdfsRacks

function New-isiNdmpSettingsVariable{
<#
.SYNOPSIS
	New Protocols Ndmp Settings Variable

.DESCRIPTION
	Create a preferred NDMP environment variable.

.PARAMETER id
	Path id

.PARAMETER name
	The name of environment variable.

.PARAMETER path
	The backup path.

.PARAMETER value
	The value of environment variable.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$path,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$value,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$parameter1 = $id
			$BoundParameters.Remove('id') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/protocols/ndmp/settings/variables/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNdmpSettingsVariable

function New-isiNdmpUsers{
<#
.SYNOPSIS
	New Protocols Ndmp Users

.DESCRIPTION
	Created a new user.

.PARAMETER name
	A unique user name for NDMP administrator.

.PARAMETER password
	The password for the NDMP administrator.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/protocols/ndmp/users" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNdmpUsers

function New-isiNfsAliases{
<#
.SYNOPSIS
	New Nfs Aliases

.DESCRIPTION
	Create a new NFS alias.

.PARAMETER health
	Specifies whether the alias is usable.

.PARAMETER name
	Specifies the name by which the alias can be referenced.

.PARAMETER path
	Specifies the path to which the alias points.

.PARAMETER zone
	Specifies the zone in which the alias is valid.

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$health,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/2/protocols/nfs/aliases" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsAliases

function New-isiNfsExportsv1{
<#
.SYNOPSIS
	New Nfs Exports

.DESCRIPTION
	Create a new NFS export.

.PARAMETER all_dirs
	If true, all directories under the specified paths are mountable.

.PARAMETER block_size
	The block size returned by the NFS STATFS procedure.

.PARAMETER can_set_time
	If true, the client may  set file  times using the NFS SETATTR request.  This  option is advisory and the server always behaves as if it is true.

.PARAMETER clients
	Clients that have access to the export.

.PARAMETER commit_asynchronous
	If true, allows NFS  commit  requests to  execute asynchronously.

.PARAMETER description
	A human readable description of the export.

.PARAMETER directory_transfer_size
	The preferred size for directory read operations.  This option is advisory.

.PARAMETER encoding
	The character encoding of clients connecting to the export.

.PARAMETER map_all
	The user and groups that non-root clients are mapped to.

.PARAMETER map_full
	If true, user mappings queries the OneFS user database.  If false, only local authentication is queried.

.PARAMETER map_lookup_uid
	If true, incoming UIDs are mapped to users in the OneFS user database.  If false, incoming UIDs are applied directly to file operations.

.PARAMETER map_retry
	Determines whether lookups for users specified in map_all or map_root are retried if the look fails.

.PARAMETER map_root
	The user and groups that root clients are mapped to.

.PARAMETER max_file_size
	The maximum file size in the export.

.PARAMETER paths
	The paths under /ifs that are exported.

.PARAMETER readdirplus
	If true, readdirplus requests are enabled.

.PARAMETER readdirplus_prefetch
	Sets the number of directory entries that will be prefetched when a readdirplus request is processed.

.PARAMETER read_only
	If true, the export is read-only.

.PARAMETER read_only_clients
	Clients that have read only access to the export.

.PARAMETER read_transfer_max_size
	The maximum buffer size that clients should use on NFS read requests.  This option is advisory.

.PARAMETER read_transfer_multiple
	The preferred multiple size for NFS read requests.  This option is advisory.

.PARAMETER read_transfer_size
	The optimal size for NFS read requests.  This option is advisory.

.PARAMETER read_write_clients
	Clients that have read and write access to the export, even if the export is read-only.

.PARAMETER return_32bit_file_ids
	Limits the size of file identifiers returned by NFSv3+ to 32-bit values.

.PARAMETER root_clients
	Clients that have root access to the export.

.PARAMETER security_flavors
	The authentication flavors that are supported for this export.

.PARAMETER setattr_asynchronous
	If true, allows setattr operations to execute asynchronously.

.PARAMETER snapshot
	Use this snapshot for all mounts.

.PARAMETER symlinks
	If true, paths reachable by symlinks are exported.

.PARAMETER time_delta
	The resolution of all time values that are returned to clients.

.PARAMETER write_datasync_action
	The action to be taken when an NFSv3+ datasync write is requested.

.PARAMETER write_datasync_reply
	The stability disposition returned when an NFSv3+ datasync write is processed.

.PARAMETER write_filesync_action
	The action to be taken when an NFSv3+ filesync write is requested.

.PARAMETER write_filesync_reply
	The stability disposition returned when an NFSv3+ filesync write is processed.

.PARAMETER write_transfer_max_size
	The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The action to be taken when an NFSv3+ unstable write is requested.

.PARAMETER write_unstable_reply
	The stability disposition returned when an NFSv3+ unstable write is processed.

.PARAMETER enforce
	If true, the export will be created even if it conflicts with another export.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$max_file_size,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][object]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][object]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][object]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][object]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][object]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][object]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
				$BoundParameters.Remove('enforce') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/protocols/nfs/exports" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsExportsv1

function New-isiNfsExportsv2{
<#
.SYNOPSIS
	New Nfs Exports

.DESCRIPTION
	Create a new NFS export.

.PARAMETER all_dirs
	True if all directories under the specified paths are mountable.

.PARAMETER block_size
	Specifies the block size returned by the NFS statfs procedure.

.PARAMETER can_set_time
	True if the client can set file times through the NFS set attribute request. This parameter does not affect server behavior, but is included to accommoate legacy client requirements.

.PARAMETER case_insensitive
	True if the case is ignored for file names. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER case_preserving
	True if the case is preserved for file names. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER chown_restricted
	True if the superuser can change file ownership. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER clients
	Specifies the clients with root access to the export.

.PARAMETER commit_asynchronous
	True if NFS  commit  requests execute asynchronously.

.PARAMETER description
	Specifies the user-defined string that is used to identify the export.

.PARAMETER directory_transfer_size
	Specifies the preferred size for directory read operations. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER encoding
	Specifies the default character set encoding of the clients connecting to the export, unless otherwise specified.

.PARAMETER link_max
	Specifies the reported maximum number of links to a file. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER map_all
	Specifies the users and groups to which non-root and root clients are mapped.

.PARAMETER map_failure
	Specifies the users and groups to which clients should be mapped to if authentication fails.

.PARAMETER map_full
	True if user mappings query the OneFS user database. When set to false, user mappings only query local authentication.

.PARAMETER map_lookup_uid
	True if incoming user IDs (UIDs) are mapped to users in the OneFS user database. When set to false, incoming UIDs are applied directly to file operations.

.PARAMETER map_non_root
	Specifies the users and groups to which non-root clients are mapped.

.PARAMETER map_retry
	Determines whether searches for users specified in 'map_all', 'map_root' or 'map_nonroot' are retried if the search fails.

.PARAMETER map_root
	Specifies the users and groups to which root clients are mapped.

.PARAMETER max_file_size
	Specifies the maximum file size for any file accessed from the export. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER name_max_size
	Specifies the reported maximum length of a file name. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER no_truncate
	True if long file names result in an error. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER paths
	Specifies the paths under /ifs that are exported.

.PARAMETER readdirplus
	True if 'readdirplus' requests are enabled. Enabling this property might improve network performance and is only available for NFSv3.

.PARAMETER readdirplus_prefetch
	Sets the number of directory entries that are prefetched when a 'readdirplus' request is processed. (Deprecated.)

.PARAMETER read_only
	True if the export is set to read-only.

.PARAMETER read_only_clients
	Specifies the clients with read-only access to the export.

.PARAMETER read_transfer_max_size
	Specifies the maximum buffer size that clients should use on NFS read requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER read_transfer_multiple
	Specifies the preferred multiple size for NFS read requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER read_transfer_size
	Specifies the preferred size for NFS read requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER read_write_clients
	Specifies the clients with both read and write access to the export, even when the export is set to read-only.

.PARAMETER return_32bit_file_ids
	Limits the size of file identifiers returned by NFSv3+ to 32-bit values.

.PARAMETER root_clients
	Clients that have root access to the export.

.PARAMETER security_flavors
	Specifies the authentication types that are supported for this export.

.PARAMETER setattr_asynchronous
	True if set attribute operations execute asynchronously.

.PARAMETER snapshot
	Specifies the snapshot for all mounts.

.PARAMETER symlinks
	True if symlinks are supported. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER time_delta
	Specifies the resolution of all time values that are returned to the clients

.PARAMETER write_datasync_action
	Specifies the action to be taken when an NFSv3+ datasync write is requested.

.PARAMETER write_datasync_reply
	Specifies the stability disposition returned when an NFSv3+ datasync write is processed.

.PARAMETER write_filesync_action
	Specifies the action to be taken when an NFSv3+ filesync write is requested.

.PARAMETER write_filesync_reply
	Specifies the stability disposition returned when an NFSv3+ filesync write is processed.

.PARAMETER write_transfer_max_size
	Specifies the maximum buffer size that clients should use on NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_transfer_multiple
	Specifies the preferred multiple size for NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_transfer_size
	Specifies the preferred multiple size for NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_unstable_action
	Specifies the action to be taken when an NFSv3+ unstable write is requested.

.PARAMETER write_unstable_reply
	Specifies the stability disposition returned when an NFSv3+ unstable write is processed.

.PARAMETER zone
	Specifies the zone in which the export is valid.

.PARAMETER enforce
	If true, the export will be created even if it conflicts with another export.

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$case_insensitive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$case_preserving,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$chown_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$link_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][object]$map_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][object]$map_non_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$name_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$no_truncate,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][object]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][object]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][object]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][object]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][object]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][object]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=49)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=50)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
				$BoundParameters.Remove('enforce') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/2/protocols/nfs/exports" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsExportsv2
Set-Alias New-isiNfsExports -Value New-isiNfsExportsv2
Export-ModuleMember -Alias New-isiNfsExports

function New-isiNfsNetgroupCheck{
<#
.SYNOPSIS
	New Protocols Nfs Netgroup Check

.DESCRIPTION
	Update the NFS netgroups in the cache.

.PARAMETER host
	IP address of node to update. If unspecified, the local nodes cache is updated.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$host,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($host){
				$queryArguments += 'host=' + $host
				$BoundParameters.Remove('host') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/protocols/nfs/netgroup/check" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsNetgroupCheck

function New-isiNfsNetgroupFlush{
<#
.SYNOPSIS
	New Protocols Nfs Netgroup Flush

.DESCRIPTION
	Flush the NFS netgroups in the cache.

.PARAMETER host
	IP address of node to flush. If unspecified, all nodes on the cluster are flushed.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$host,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($host){
				$queryArguments += 'host=' + $host
				$BoundParameters.Remove('host') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/protocols/nfs/netgroup/flush" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsNetgroupFlush

function New-isiNfsNlmSessionsCheck{
<#
.SYNOPSIS
	New Protocols Nfs Nlm Sessions Check

.DESCRIPTION
	Perform an active scan for lost NFSv3 locks.

.PARAMETER ip
	An IP address for which NSM has client records

.PARAMETER access_zone
	Represents an extant auth zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$ip,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($ip){
				$queryArguments += 'ip=' + $ip
				$BoundParameters.Remove('ip') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/protocols/nfs/nlm/sessions-check" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsNlmSessionsCheck

function New-isiNfsReloadv1{
<#
.SYNOPSIS
	New Nfs Reload

.DESCRIPTION
	Reload default NFS export configuration.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/protocols/nfs/reload" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsReloadv1

function New-isiNfsReloadv2{
<#
.SYNOPSIS
	New Nfs Reload

.DESCRIPTION
	Reload default NFS export configuration.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/2/protocols/nfs/reload" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsReloadv2
Set-Alias New-isiNfsReload -Value New-isiNfsReloadv2
Export-ModuleMember -Alias New-isiNfsReload

function New-isiNfsReloadv3{
<#
.SYNOPSIS
	New Protocols Nfs Reload

.DESCRIPTION
	Reload default NFS export configuration.

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/protocols/nfs/reload" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsReloadv3

function New-isiNtpServers{
<#
.SYNOPSIS
	New Protocols Ntp Servers

.DESCRIPTION
	Create an NTP server entry.

.PARAMETER key
	Key value from key_file that maps to this server.

.PARAMETER name
	NTP server name.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$key,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/protocols/ntp/servers" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNtpServers

function New-isiSmbLogLevelFilters{
<#
.SYNOPSIS
	New Protocols Smb Log Level Filters

.DESCRIPTION
	Add an SMB log filter.

.PARAMETER ip_addrs
	Array of client IP addresses to filter against.

.PARAMETER level
	Logging level of the filter.
	Valid inputs: always,error,warning,info,verbose,debug,trace

.PARAMETER ops
	Array of SMB operations to filter against.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$ip_addrs,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('always','error','warning','info','verbose','debug','trace')][string]$level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$ops,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/protocols/smb/log-level/filters" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSmbLogLevelFilters

function New-isiSmbSharesv1{
<#
.SYNOPSIS
	New Smb Shares

.DESCRIPTION
	Create a new share.

.PARAMETER access_based_enumeration
	Only enumerate files and folders the requesting user has access to.

.PARAMETER access_based_enumeration_root_only
	Access-based enumeration on only the root directory of the share.

.PARAMETER allow_delete_readonly
	Allow deletion of read-only files in the share.

.PARAMETER allow_execute_always
	Allows users to execute files they have read rights for.

.PARAMETER allow_variable_expansion
	Allow automatic expansion of variables for home directories.

.PARAMETER auto_create_directory
	Automatically create home directories.

.PARAMETER browsable
	Share is visible in net view and the browse list.

.PARAMETER change_notify
	Level of change notification alerts on the share.
	Valid inputs: all,norecurse,none

.PARAMETER create_path
	Create path if does not exist.

.PARAMETER create_permissions
	Create permissions for new files and directories in share.
	Valid inputs: default acl,inherit mode bits,use create mask and mode

.PARAMETER csc_policy
	Client-side caching policy for the shares.
	Valid inputs: manual,documents,programs,none

.PARAMETER description
	Description for this SMB share.

.PARAMETER directory_create_mask
	Directory create mask bits.

.PARAMETER directory_create_mode
	Directory create mode bits.

.PARAMETER file_create_mask
	File create mask bits.

.PARAMETER file_create_mode
	File create mode bits.

.PARAMETER hide_dot_files
	Hide files and directories that begin with a period '.'.

.PARAMETER host_acl
	An ACL expressing which hosts are allowed access. A deny clause must be the final entry.

.PARAMETER impersonate_guest
	Specify the condition in which user access is done as the guest account.
	Valid inputs: always,bad user,never

.PARAMETER impersonate_user
	User account to be used as guest account.

.PARAMETER inheritable_path_acl
	Set the inheritable ACL on the share path.

.PARAMETER mangle_byte_start
	Specifies the wchar_t starting point for automatic byte mangling.

.PARAMETER mangle_map
	Character mangle map.

.PARAMETER name
	Share name.

.PARAMETER ntfs_acl_support
	Support NTFS ACLs on files and directories.

.PARAMETER oplocks
	Support oplocks.

.PARAMETER path
	Path of share within /ifs.

.PARAMETER permissions
	Specifies an ordered list of permission modifications.

.PARAMETER run_as_root
	Allow account to run as root.

.PARAMETER strict_flush
	Handle SMB flush operations.

.PARAMETER strict_locking
	Specifies whether byte range locks contend against SMB I/O.

.PARAMETER zone
	Name of the access zone to which to move this SMB share

.PARAMETER access_zone
	Zone which contains this share.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_variable_expansion,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$auto_create_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$browsable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('all','norecurse','none')][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][ValidateSet('always','bad user','never')][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$inheritable_path_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$mangle_map,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$oplocks,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$run_as_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/protocols/smb/shares" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSmbSharesv1
Set-Alias New-isiSmbShares -Value New-isiSmbSharesv1
Export-ModuleMember -Alias New-isiSmbShares

function New-isiSmbSharesv3{
<#
.SYNOPSIS
	New Protocols Smb Shares

.DESCRIPTION
	Create a new share.

.PARAMETER access_based_enumeration
	Only enumerate files and folders the requesting user has access to.

.PARAMETER access_based_enumeration_root_only
	Access-based enumeration on only the root directory of the share.

.PARAMETER allow_delete_readonly
	Allow deletion of read-only files in the share.

.PARAMETER allow_execute_always
	Allows users to execute files they have read rights for.

.PARAMETER allow_variable_expansion
	Allow automatic expansion of variables for home directories.

.PARAMETER auto_create_directory
	Automatically create home directories.

.PARAMETER browsable
	Share is visible in net view and the browse list.

.PARAMETER ca_timeout
	Persistent open timeout for the share.

.PARAMETER ca_write_integrity
	Specify the level of write-integrity on continuously available shares.
	Valid inputs: none,write-read-coherent,full

.PARAMETER change_notify
	Level of change notification alerts on the share.
	Valid inputs: all,norecurse,none

.PARAMETER continuously_available
	Specify if persistent opens are allowed on the share.

.PARAMETER create_path
	Create path if does not exist.

.PARAMETER create_permissions
	Create permissions for new files and directories in share.
	Valid inputs: default acl,inherit mode bits,use create mask and mode

.PARAMETER csc_policy
	Client-side caching policy for the shares.
	Valid inputs: manual,documents,programs,none

.PARAMETER description
	Description for this SMB share.

.PARAMETER directory_create_mask
	Directory create mask bits.

.PARAMETER directory_create_mode
	Directory create mode bits.

.PARAMETER file_create_mask
	File create mask bits.

.PARAMETER file_create_mode
	File create mode bits.

.PARAMETER file_filtering_enabled
	Enables file filtering on this zone.

.PARAMETER file_filter_extensions
	Specifies the list of file extensions.

.PARAMETER file_filter_type
	Specifies if filter list is for deny or allow. Default is deny.
	Valid inputs: deny,allow

.PARAMETER hide_dot_files
	Hide files and directories that begin with a period '.'.

.PARAMETER host_acl
	An ACL expressing which hosts are allowed access. A deny clause must be the final entry.

.PARAMETER impersonate_guest
	Specify the condition in which user access is done as the guest account.
	Valid inputs: always,bad user,never

.PARAMETER impersonate_user
	User account to be used as guest account.

.PARAMETER inheritable_path_acl
	Set the inheritable ACL on the share path.

.PARAMETER mangle_byte_start
	Specifies the wchar_t starting point for automatic byte mangling.

.PARAMETER mangle_map
	Character mangle map.

.PARAMETER name
	Share name.

.PARAMETER ntfs_acl_support
	Support NTFS ACLs on files and directories.

.PARAMETER oplocks
	Support oplocks.

.PARAMETER path
	Path of share within /ifs.

.PARAMETER permissions
	Specifies an ordered list of permission modifications.

.PARAMETER run_as_root
	Allow account to run as root.

.PARAMETER strict_ca_lockout
	Specifies if persistent opens would do strict lockout on the share.

.PARAMETER strict_flush
	Handle SMB flush operations.

.PARAMETER strict_locking
	Specifies whether byte range locks contend against SMB I/O.

.PARAMETER zone
	Name of the access zone to which to move this SMB share

.PARAMETER access_zone
	Zone which contains this share.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_variable_expansion,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$auto_create_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$browsable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$ca_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('none','write-read-coherent','full')][string]$ca_write_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('all','norecurse','none')][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$continuously_available,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$file_filtering_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][array]$file_filter_extensions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][ValidateSet('deny','allow')][string]$file_filter_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][ValidateSet('always','bad user','never')][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$inheritable_path_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$mangle_map,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$oplocks,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][array]$permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][array]$run_as_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$strict_ca_lockout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/protocols/smb/shares" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSmbSharesv3

function New-isiSwiftAccounts{
<#
.SYNOPSIS
	New Protocols Swift Accounts

.DESCRIPTION
	Create a new Swift account

.PARAMETER id
	Unique id of swift account

.PARAMETER name
	Name of Swift account

.PARAMETER swiftgroup
	Group with filesystem ownership of this account

.PARAMETER swiftuser
	User with filesystem ownership of this account

.PARAMETER users
	Users who are allowed to access Swift account

.PARAMETER zone
	Name of access zone for account

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$swiftgroup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$swiftuser,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/protocols/swift/accounts" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSwiftAccounts

function New-isiQuotas{
<#
.SYNOPSIS
	New Quotas

.DESCRIPTION
	Create a new quota.

.PARAMETER container
	If true, SMB shares using the quota directory see the quota thresholds as share size.

.PARAMETER enforced
	True if the quota provides enforcement, otherwise a accounting quota.

.PARAMETER force
	Force creation of quotas on the root of /ifs.

.PARAMETER include_snapshots
	If true, quota governs snapshot data as well as head data.

.PARAMETER path
	The /ifs path governed.

.PARAMETER persona
	Specifies properties for a persona, which consists of either a 'type' and a 'name' or an 'ID'.

.PARAMETER thresholds
	

.PARAMETER thresholds_include_overhead
	If true, thresholds apply to data plus filesystem overhead required to store the data (i.e. 'physical' usage).

.PARAMETER type
	The type of quota.
	Valid inputs: directory,user,group,default-user,default-group

.PARAMETER access_zone
	Optional named zone to use for user and group resolution.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$container,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enforced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$force,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$include_snapshots,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$persona,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$thresholds,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$thresholds_include_overhead,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('directory','user','group','default-user','default-group')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/quota/quotas" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiQuotas

function New-isiQuotaNotifications{
<#
.SYNOPSIS
	New Quota Notifications

.DESCRIPTION
	Create a new notification rule specific to this quota.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER action_alert
	Send alert when rule matches.

.PARAMETER action_email_address
	Email a specific email address when rule matches.

.PARAMETER action_email_owner
	Email quota domain owner when rule matches.

.PARAMETER condition
	The condition detected.
	Valid inputs: exceeded,denied,violated,expired

.PARAMETER email_template
	Path of optional /ifs template file used for email actions.

.PARAMETER holdoff
	Time to wait between detections for rules triggered by user actions.

.PARAMETER schedule
	Schedule for rules that repeatedly notify.

.PARAMETER threshold
	The quota threshold detected.
	Valid inputs: hard,soft,advisory

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$action_email_owner,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('exceeded','denied','violated','expired')][string]$condition,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$schedule,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('hard','soft','advisory')][string]$threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('quota_id')){
				$parameter1 = $quota_id
				$BoundParameters.Remove('quota_id') | out-null
			} else {
				$parameter1 = $quota_name
				$BoundParameters.Remove('quota_name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/quota/quotas/$parameter1/notifications" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiQuotaNotifications

function New-isiQuotaReports{
<#
.SYNOPSIS
	New Quota Reports

.DESCRIPTION
	Create a new report. The type of this report is 'manual'; it is also sometimes called 'live' or 'ad-hoc'.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/quota/reports" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiQuotaReports

function New-isiQuotaSettingsMappings{
<#
.SYNOPSIS
	New Quota Settings Mappings

.DESCRIPTION
	Create a new rule. The new rule must not conflict with an existing rule (e.g. match both the type and domain fields).

.PARAMETER domain
	The FQDN of the source domain to map.

.PARAMETER mapping
	The FQDN of destination domain to map to.

.PARAMETER type
	The authentication provider type.
	Valid inputs: ad,local,nis,ldap

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$domain,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$mapping,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('ad','local','nis','ldap')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/quota/settings/mappings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiQuotaSettingsMappings

function New-isiQuotaSettingsNotifications{
<#
.SYNOPSIS
	New Quota Settings Notifications

.DESCRIPTION
	Create a new global notification rule.

.PARAMETER action_alert
	Send alert when rule matches.

.PARAMETER action_email_address
	Email a specific email address when rule matches.

.PARAMETER action_email_owner
	Email quota domain owner when rule matches.

.PARAMETER condition
	The condition detected.
	Valid inputs: exceeded,denied,violated,expired

.PARAMETER email_template
	Path of optional /ifs template file used for email actions.

.PARAMETER holdoff
	Time to wait between detections for rules triggered by user actions.

.PARAMETER schedule
	Schedule for rules that repeatedly notify.

.PARAMETER threshold
	The quota threshold detected.
	Valid inputs: hard,soft,advisory

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$action_email_owner,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('exceeded','denied','violated','expired')][string]$condition,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$schedule,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('hard','soft','advisory')][string]$threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/quota/settings/notifications" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiQuotaSettingsNotifications

function New-isiSnapshotAliases{
<#
.SYNOPSIS
	New Snapshot Aliases

.DESCRIPTION
	Create a new snapshot alias.

.PARAMETER name
	The user or system supplied snapshot name.

.PARAMETER target
	Snapshot name target for the alias.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$target,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/aliases" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.aliases
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotAliases

function New-isiSnapshotChangelists{
<#
.SYNOPSIS
	New Snapshot Changelists

.DESCRIPTION
	Create a new changelist.

.PARAMETER id
	The system ID given to the changelist.

.PARAMETER job_id
	The ID of the job which created the changelist.

.PARAMETER num_entries
	Number of LIN entries in changelist.

.PARAMETER root_path
	Root path of all LINs in changelist.

.PARAMETER snap1
	The lower snapid used to compute the changelist.

.PARAMETER snap2
	The higher snapid used to compute the changelist.

.PARAMETER status
	Status of changelist.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$job_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$num_entries,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$root_path,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$snap1,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$snap2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/changelists" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotChangelists

function New-isiSnapshotRepstates{
<#
.SYNOPSIS
	New Snapshot Repstates

.DESCRIPTION
	Create a new repstates.

.PARAMETER id
	The system ID given to the repstate.

.PARAMETER snap1
	The lower snapid used to compute the repstate.

.PARAMETER snap2
	The higher snapid used to compute the repstate.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$snap1,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$snap2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/repstates" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotRepstates

function New-isiSnapshotSchedulesv1{
<#
.SYNOPSIS
	New Snapshot Schedules

.DESCRIPTION
	Create a new schedule.

.PARAMETER alias
	Alias name to create for each snapshot.

.PARAMETER duration
	Time in seconds added to creation time to construction expiration time.

.PARAMETER name
	The schedule name.

.PARAMETER path
	The /ifs path snapshotted.

.PARAMETER pattern
	Pattern expanded with strftime to create snapshot names.

.PARAMETER schedule
	The isidate compatible natural language description of the schedule.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$duration,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$path,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$pattern,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/schedules" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotSchedulesv1
Set-Alias New-isiSnapshotSchedules -Value New-isiSnapshotSchedulesv1
Export-ModuleMember -Alias New-isiSnapshotSchedules

function New-isiSnapshotSchedulesv3{
<#
.SYNOPSIS
	New Snapshot Schedules

.DESCRIPTION
	Create a new schedule.

.PARAMETER alias
	Alias name to create for each snapshot.

.PARAMETER duration
	Time in seconds added to creation time to construction expiration time.

.PARAMETER name
	The schedule name.

.PARAMETER path
	The /ifs path snapshotted.

.PARAMETER pattern
	Pattern expanded with strftime to create snapshot names.

.PARAMETER schedule
	The isidate compatible natural language description of the schedule.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$duration,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$path,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$pattern,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/snapshot/schedules" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotSchedulesv3

function New-isiSnapshots{
<#
.SYNOPSIS
	New Snapshots

.DESCRIPTION
	Create a new snapshot.

.PARAMETER alias
	Alias name to create for this snapshot. If null, remove any alias.

.PARAMETER expires
	The Unix Epoch time the snapshot will expire and be eligible for automatic deletion.

.PARAMETER name
	The user or system supplied snapshot name. This will be null for snapshots pending delete.

.PARAMETER path
	The /ifs path snapshotted.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/snapshots" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshots

function New-isiSnapshotLocks{
<#
.SYNOPSIS
	New Snapshot Locks

.DESCRIPTION
	Create a new lock on this snapshot.

.PARAMETER snapshot_id
	Snapshot snapshot_id

.PARAMETER snapshot_name
	Snapshot snapshot_name

.PARAMETER comment
	Free form comment.

.PARAMETER expires
	The Unix Epoch time the snapshot lock will expire and be eligible for automatic deletion.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$comment,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('snapshot_id')){
				$parameter1 = $snapshot_id
				$BoundParameters.Remove('snapshot_id') | out-null
			} else {
				$parameter1 = $snapshot_name
				$BoundParameters.Remove('snapshot_name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/snapshots/$parameter1/locks" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotLocks

function New-isiStoragepoolCompatibilitiesClassActive{
<#
.SYNOPSIS
	New Storagepool Compatibilities Class Active

.DESCRIPTION
	Create a new compatibility

.PARAMETER assess
	Do not create compatibility, only assess if creation is possible.

.PARAMETER class_1
	The first class in the desired compatibility

.PARAMETER class_2
	The second class in the desired compatibility

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$assess,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$class_1,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$class_2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/storagepool/compatibilities/class/active" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolCompatibilitiesClassActive

function New-isiStoragepoolCompatibilitiesSSDActivev1{
<#
.SYNOPSIS
	New Storagepool Compatibilities SSD Active

.DESCRIPTION
	Create a new ssd compatibility

.PARAMETER assess
	Do not create ssd compatibility, only assess if creation is possible.

.PARAMETER class_1
	The node class of the desired ssd compatibility

.PARAMETER class_2
	The optional second node class to turn on ssd compatibility

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$assess,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$class_1,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$class_2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/storagepool/compatibilities/ssd/active" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolCompatibilitiesSSDActivev1
Set-Alias New-isiStoragepoolCompatibilitiesSSDActive -Value New-isiStoragepoolCompatibilitiesSSDActivev1
Export-ModuleMember -Alias New-isiStoragepoolCompatibilitiesSSDActive

function New-isiStoragepoolCompatibilitiesSSDActivev3{
<#
.SYNOPSIS
	New Storagepool Compatibilities Ssd Active

.DESCRIPTION
	Create a new ssd compatibility

.PARAMETER assess
	Do not create ssd compatibility, only assess if creation is possible.

.PARAMETER class_1
	The node class of the desired ssd compatibility

.PARAMETER class_2
	The optional second node class to turn on ssd compatibility

.PARAMETER count
	Is this SSD Compatibility Count Compatible.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$assess,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$class_1,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$class_2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/storagepool/compatibilities/ssd/active" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolCompatibilitiesSSDActivev3

function New-isiStoragepoolNodepoolsv1{
<#
.SYNOPSIS
	New Storagepool Nodepools

.DESCRIPTION
	Create a new node pool.

.PARAMETER l3
	Use SSDs in this node pool for L3 cache.

.PARAMETER lnns
	The nodes that are part of this node pool.

.PARAMETER name
	The node pool name.

.PARAMETER protection_policy
	The node pool protection policy.

.PARAMETER tier
	The name or ID of the node pool's tier, if it is in a tier.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$l3,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$lnns,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$protection_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$tier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/storagepool/nodepools" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolNodepoolsv1
Set-Alias New-isiStoragepoolNodepools -Value New-isiStoragepoolNodepoolsv1
Export-ModuleMember -Alias New-isiStoragepoolNodepools

function New-isiStoragepoolNodepoolsv3{
<#
.SYNOPSIS
	New Storagepool Nodepools

.DESCRIPTION
	Create a new node pool.

.PARAMETER l3
	Use SSDs in this node pool for L3 cache.

.PARAMETER lnns
	The nodes that are part of this node pool.

.PARAMETER name
	The node pool name.

.PARAMETER protection_policy
	The node pool protection policy.

.PARAMETER tier
	The name or ID of the node pool's tier, if it is in a tier.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$l3,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$lnns,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$protection_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$tier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/storagepool/nodepools" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolNodepoolsv3

function New-isiStoragepoolTiers{
<#
.SYNOPSIS
	New Storagepool Tiers

.DESCRIPTION
	Create a new tier.

.PARAMETER children
	The names or IDs of the tier's children.

.PARAMETER name
	The tier name.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$children,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/storagepool/tiers" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolTiers

function New-isiSyncJobsv1{
<#
.SYNOPSIS
	New Sync Jobs

.DESCRIPTION
	Start a SyncIQ job.

.PARAMETER action
	The action to be taken by this job.
	Valid inputs: resync_prep,allow_write,allow_write_revert,test

.PARAMETER id
	The ID or Name of the policy

.PARAMETER log_level
	Only valid for allow_write, and allow_write_revert; specify the desired logging level, will be stored in the logs for isi_migrate, defaults to 'info'.
	Valid inputs: fatal,error,notice,info,copy,debug,trace

.PARAMETER source_snapshot
	An optional snapshot to copy/sync from.

.PARAMETER workers_per_node
	Only valid for allow_write, and allow_write_revert; specify the desired workers per node, defaults to 3.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('resync_prep','allow_write','allow_write_revert','test')][string]$action,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('fatal','error','notice','info','copy','debug','trace')][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$source_snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncJobsv1
Set-Alias New-isiSyncJobs -Value New-isiSyncJobsv1
Export-ModuleMember -Alias New-isiSyncJobs

function New-isiSyncJobsv3{
<#
.SYNOPSIS
	New Sync Jobs

.DESCRIPTION
	Start a SyncIQ job.

.PARAMETER action
	The action to be taken by this job.
	Valid inputs: resync_prep,allow_write,allow_write_revert,test

.PARAMETER id
	The ID or Name of the policy

.PARAMETER log_level
	Only valid for allow_write, and allow_write_revert; specify the desired logging level, will be stored in the logs for isi_migrate, defaults to 'info'.
	Valid inputs: fatal,error,notice,info,copy,debug,trace

.PARAMETER source_snapshot
	An optional snapshot to copy/sync from.

.PARAMETER workers_per_node
	Only valid for allow_write, and allow_write_revert; specify the desired workers per node, defaults to 3.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('resync_prep','allow_write','allow_write_revert','test')][string]$action,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('fatal','error','notice','info','copy','debug','trace')][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$source_snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/sync/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncJobsv3

function New-isiSyncPoliciesv1{
<#
.SYNOPSIS
	New Sync Policies

.DESCRIPTION
	Create a SyncIQ policy.

.PARAMETER action
	If 'copy', source files will be copied to the target cluster.  If 'sync', the target directory will be made an image of the source directory:  Files and directories that have been deleted on the source, have been moved within the target directory, or no longer match the selection criteria will be deleted from the target directory.
	Valid inputs: copy,sync

.PARAMETER burst_mode
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable UDP-based data transfer.

.PARAMETER changelist
	If true, retain previous source snapshot and incremental repstate, both of which are required for changelist creation.

.PARAMETER check_integrity
	If true, the sync target performs cyclic redundancy checks (CRC) on the data as it is received.

.PARAMETER description
	User-assigned description of this sync policy.

.PARAMETER disable_file_split
	NOTE: This field should not be changed without the help of Isilon support.  If true, the 7.2+ file splitting capability will be disabled.

.PARAMETER disable_fofb
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable sync failover/failback.

.PARAMETER disable_stf
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable the 6.5+ STF based data transfer and uses only treewalk.

.PARAMETER enabled
	If true, jobs will be automatically run based on this policy, according to its schedule.

.PARAMETER expected_dataloss
	NOTE: This field should not be changed without the help of Isilon support.  Continue sending files even with the corrupted filesystem.

.PARAMETER file_matching_pattern
	A file matching pattern, organized as an OR'ed set of AND'ed file criteria, for example ((a AND b) OR (x AND y)) used to define a set of files with specific properties.  Policies of type 'sync' cannot use 'path' or time criteria in their matching patterns, but policies of type 'copy' can use all listed criteria.

.PARAMETER force_interface
	NOTE: This field should not be changed without the help of Isilon support.  Determines whether data is sent only through the subnet and pool specified in the "source_network" field. This option can be useful if there are multiple interfaces for the given source subnet.  If you enable this option, the net.inet.ip.choose_ifa_by_ipsrc sysctl should be set.

.PARAMETER log_level
	Severity an event must reach before it is logged.
	Valid inputs: fatal,error,notice,info,copy,debug,trace

.PARAMETER log_removed_files
	If true, the system will log any files or directories that are deleted due to a sync.

.PARAMETER name
	User-assigned name of this sync policy.

.PARAMETER password
	The password for the target cluster.  This field is not readable.

.PARAMETER report_max_age
	Length of time (in seconds) a policy report will be stored.

.PARAMETER report_max_count
	Maximum number of policy reports that will be stored on the system.

.PARAMETER restrict_target_network
	If you specify true, and you specify a SmartConnect zone in the "target_host" field, replication policies will connect only to nodes in the specified SmartConnect zone.  If you specify false, replication policies are not restricted to specific nodes on the target cluster.

.PARAMETER schedule
	The schedule on which new jobs will be run for this policy.

.PARAMETER source_exclude_directories
	Directories that will be excluded from the sync.  Modifying this field will result in a full synchronization of all data.

.PARAMETER source_include_directories
	Directories that will be included in the sync.  Modifying this field will result in a full synchronization of all data.

.PARAMETER source_network
	Restricts replication policies on the local cluster to running on the specified subnet and pool.

.PARAMETER source_root_path
	The root directory on the source cluster the files will be synced from.  Modifying this field will result in a full synchronization of all data.

.PARAMETER source_snapshot_archive
	If true, archival snapshots of the source data will be taken on the source cluster before a sync.

.PARAMETER source_snapshot_expiration
	The length of time in seconds to keep snapshots on the source cluster.

.PARAMETER source_snapshot_pattern
	The name pattern for snapshots taken on the source cluster before a sync.

.PARAMETER target_compare_initial_sync
	If true, the target creates diffs against the original sync.

.PARAMETER target_detect_modifications
	If true, target cluster will detect if files have been changed on the target by legacy tree walk syncs.

.PARAMETER target_host
	Hostname or IP address of sync target cluster.  Modifying the target cluster host can result in the policy being unrunnable if the new target does not match the current target association.

.PARAMETER target_path
	Absolute filesystem path on the target cluster for the sync destination.

.PARAMETER target_snapshot_alias
	The alias of the snapshot taken on the target cluster after the sync completes. A value of @DEFAULT will reset this field to the default creation value.

.PARAMETER target_snapshot_archive
	If true, archival snapshots of the target data will be taken on the target cluster after successful sync completions.

.PARAMETER target_snapshot_expiration
	The length of time in seconds to keep snapshots on the target cluster.

.PARAMETER target_snapshot_pattern
	The name pattern for snapshots taken on the target cluster after the sync completes.  A value of @DEFAULT will reset this field to the default creation value.

.PARAMETER workers_per_node
	The number of worker threads on a node performing a sync.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('copy','sync')][string]$action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$burst_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$changelist,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$check_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$disable_file_split,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$disable_fofb,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$disable_stf,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$expected_dataloss,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$force_interface,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateSet('fatal','error','notice','info','copy','debug','trace')][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$log_removed_files,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$report_max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$report_max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$restrict_target_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][array]$source_exclude_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][array]$source_include_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][object]$source_network,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$source_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$source_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$source_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$source_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$target_compare_initial_sync,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$target_detect_modifications,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][string]$target_host,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$target_snapshot_alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][bool]$target_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][int]$target_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$target_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/policies" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncPoliciesv1
Set-Alias New-isiSyncPolicies -Value New-isiSyncPoliciesv1
Export-ModuleMember -Alias New-isiSyncPolicies

function New-isiSyncPoliciesv3{
<#
.SYNOPSIS
	New Sync Policies

.DESCRIPTION
	Create a SyncIQ policy.

.PARAMETER accelerated_failback
	If set to true, SyncIQ will perform failback configuration tasks during the next job run, rather than waiting to perform those tasks during the failback process. Performing these tasks ahead of time will increase the speed of failback operations.

.PARAMETER action
	If 'copy', source files will be copied to the target cluster.  If 'sync', the target directory will be made an image of the source directory:  Files and directories that have been deleted on the source, have been moved within the target directory, or no longer match the selection criteria will be deleted from the target directory.
	Valid inputs: copy,sync

.PARAMETER burst_mode
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable UDP-based data transfer.

.PARAMETER changelist
	If true, retain previous source snapshot and incremental repstate, both of which are required for changelist creation.

.PARAMETER check_integrity
	If true, the sync target performs cyclic redundancy checks (CRC) on the data as it is received.

.PARAMETER cloud_deep_copy
	If set to deny, replicates all CloudPools smartlinks to the target cluster as smartlinks; if the target cluster does not support the smartlinks, the job will fail. If set to force, replicates all smartlinks to the target cluster as regular files. If set to allow, SyncIQ will attempt to replicate smartlinks to the target cluster as smartlinks; if the target cluster does not support the smartlinks, SyncIQ will replicate the smartlinks as regular files.
	Valid inputs: deny,allow,force

.PARAMETER description
	User-assigned description of this sync policy.

.PARAMETER disable_file_split
	NOTE: This field should not be changed without the help of Isilon support.  If true, the 7.2+ file splitting capability will be disabled.

.PARAMETER disable_fofb
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable sync failover/failback.

.PARAMETER disable_stf
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable the 6.5+ STF based data transfer and uses only treewalk.

.PARAMETER enabled
	If true, jobs will be automatically run based on this policy, according to its schedule.

.PARAMETER expected_dataloss
	NOTE: This field should not be changed without the help of Isilon support.  Continue sending files even with the corrupted filesystem.

.PARAMETER file_matching_pattern
	A file matching pattern, organized as an OR'ed set of AND'ed file criteria, for example ((a AND b) OR (x AND y)) used to define a set of files with specific properties.  Policies of type 'sync' cannot use 'path' or time criteria in their matching patterns, but policies of type 'copy' can use all listed criteria.

.PARAMETER force_interface
	NOTE: This field should not be changed without the help of Isilon support.  Determines whether data is sent only through the subnet and pool specified in the "source_network" field. This option can be useful if there are multiple interfaces for the given source subnet.  If you enable this option, the net.inet.ip.choose_ifa_by_ipsrc sysctl should be set.

.PARAMETER job_delay
	If --schedule is set to When-Source-Modified, the duration to wait after a modification is made before starting a job (default is 0 seconds).

.PARAMETER log_level
	Severity an event must reach before it is logged.
	Valid inputs: fatal,error,notice,info,copy,debug,trace

.PARAMETER log_removed_files
	If true, the system will log any files or directories that are deleted due to a sync.

.PARAMETER name
	User-assigned name of this sync policy.

.PARAMETER password
	The password for the target cluster.  This field is not readable.

.PARAMETER priority
	Determines the priority level of a policy. Policies with higher priority will have precedence to run over lower priority policies. Valid range is [0, 1]. Default is 0.

.PARAMETER report_max_age
	Length of time (in seconds) a policy report will be stored.

.PARAMETER report_max_count
	Maximum number of policy reports that will be stored on the system.

.PARAMETER restrict_target_network
	If you specify true, and you specify a SmartConnect zone in the "target_host" field, replication policies will connect only to nodes in the specified SmartConnect zone.  If you specify false, replication policies are not restricted to specific nodes on the target cluster.

.PARAMETER rpo_alert
	If --schedule is set to a time/date, an alert is created if the specified RPO for this policy is exceeded. The default value is 0, which will not generate RPO alerts.

.PARAMETER schedule
	The schedule on which new jobs will be run for this policy.

.PARAMETER skip_lookup
	Skip DNS lookup of target IPs.

.PARAMETER skip_when_source_unmodified
	If true and --schedule is set to a time/date, the policy will not run if no changes have been made to the contents of the source directory since the last job successfully completed.

.PARAMETER snapshot_sync_existing
	If true, snapshot-triggered syncs will include snapshots taken before policy creation time (requires --schedule when-snapshot-taken).

.PARAMETER snapshot_sync_pattern
	The naming pattern that a snapshot must match to trigger a sync when the schedule is when-snapshot-taken (default is "*").

.PARAMETER source_exclude_directories
	Directories that will be excluded from the sync.  Modifying this field will result in a full synchronization of all data.

.PARAMETER source_include_directories
	Directories that will be included in the sync.  Modifying this field will result in a full synchronization of all data.

.PARAMETER source_network
	Restricts replication policies on the local cluster to running on the specified subnet and pool.

.PARAMETER source_root_path
	The root directory on the source cluster the files will be synced from.  Modifying this field will result in a full synchronization of all data.

.PARAMETER source_snapshot_archive
	If true, archival snapshots of the source data will be taken on the source cluster before a sync.

.PARAMETER source_snapshot_expiration
	The length of time in seconds to keep snapshots on the source cluster.

.PARAMETER source_snapshot_pattern
	The name pattern for snapshots taken on the source cluster before a sync.

.PARAMETER target_compare_initial_sync
	If true, the target creates diffs against the original sync.

.PARAMETER target_detect_modifications
	If true, target cluster will detect if files have been changed on the target by legacy tree walk syncs.

.PARAMETER target_host
	Hostname or IP address of sync target cluster.  Modifying the target cluster host can result in the policy being unrunnable if the new target does not match the current target association.

.PARAMETER target_path
	Absolute filesystem path on the target cluster for the sync destination.

.PARAMETER target_snapshot_alias
	The alias of the snapshot taken on the target cluster after the sync completes. A value of @DEFAULT will reset this field to the default creation value.

.PARAMETER target_snapshot_archive
	If true, archival snapshots of the target data will be taken on the target cluster after successful sync completions.

.PARAMETER target_snapshot_expiration
	The length of time in seconds to keep snapshots on the target cluster.

.PARAMETER target_snapshot_pattern
	The name pattern for snapshots taken on the target cluster after the sync completes.  A value of @DEFAULT will reset this field to the default creation value.

.PARAMETER workers_per_node
	The number of worker threads on a node performing a sync.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$accelerated_failback,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('copy','sync')][string]$action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$burst_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$changelist,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$check_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('deny','allow','force')][string]$cloud_deep_copy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$disable_file_split,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$disable_fofb,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$disable_stf,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$expected_dataloss,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$force_interface,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$job_delay,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateSet('fatal','error','notice','info','copy','debug','trace')][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$log_removed_files,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$report_max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$report_max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$restrict_target_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$rpo_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$skip_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$skip_when_source_unmodified,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$snapshot_sync_existing,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$snapshot_sync_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$source_exclude_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$source_include_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][object]$source_network,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$source_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$source_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][int]$source_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$source_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][bool]$target_compare_initial_sync,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][bool]$target_detect_modifications,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$target_host,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][string]$target_snapshot_alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][bool]$target_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][int]$target_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][string]$target_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/sync/policies" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncPoliciesv3

function New-isiSyncPolicyReset{
<#
.SYNOPSIS
	New Sync Policy Reset

.DESCRIPTION
	Reset a SyncIQ policy incremental state and force a full sync/copy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/policies/$parameter1/reset" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncPolicyReset

function New-isiSyncReportsRotate{
<#
.SYNOPSIS
	New Sync Reports Rotate

.DESCRIPTION
	Rotate the records in the database(s).

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/reports-rotate" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.message
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncReportsRotate

function New-isiSyncRulesv1{
<#
.SYNOPSIS
	New Sync Rules

.DESCRIPTION
	Create a new SyncIQ performance rule.

.PARAMETER description
	User-entered description of this performance rule.

.PARAMETER enabled
	Whether this performance rule is currently in effect during its specified intervals.

.PARAMETER limit
	Amount the specified system resource type is limited by this rule.  Units are kb/s for bandwidth, files/s for file-count, or processing percentage used for cpu.

.PARAMETER schedule
	A schedule defining when during a week this performance rule is in effect.  If unspecified or null, the schedule will always be in effect.

.PARAMETER type
	The type of system resource this rule limits.
	Valid inputs: bandwidth,file_count,cpu

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$schedule,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('bandwidth','file_count','cpu')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/rules" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncRulesv1
Set-Alias New-isiSyncRules -Value New-isiSyncRulesv1
Export-ModuleMember -Alias New-isiSyncRules

function New-isiSyncRulesv3{
<#
.SYNOPSIS
	New Sync Rules

.DESCRIPTION
	Create a new SyncIQ performance rule.

.PARAMETER description
	User-entered description of this performance rule.

.PARAMETER enabled
	Whether this performance rule is currently in effect during its specified intervals.

.PARAMETER limit
	Amount the specified system resource type is limited by this rule.  Units are kb/s for bandwidth, files/s for file-count, processing percentage used for cpu, or percentage of maximum available workers.

.PARAMETER schedule
	A schedule defining when during a week this performance rule is in effect.  If unspecified or null, the schedule will always be in effect.

.PARAMETER type
	The type of system resource this rule limits.
	Valid inputs: bandwidth,file_count,cpu,worker

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$schedule,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('bandwidth','file_count','cpu','worker')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/sync/rules" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncRulesv3

function New-isiSyncTargetPolicyCancel{
<#
.SYNOPSIS
	New Sync Target Policy Cancel

.DESCRIPTION
	Cancel the most recent SyncIQ job for this policy from the target side.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/target/policies/$parameter1/cancel" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncTargetPolicyCancel

function New-isiUpgradeClusterAddRemainingNodes{
<#
.SYNOPSIS
	New Upgrade Cluster Add Remaining Nodes

.DESCRIPTION
	Let system absorb any remaining or new nodes inside the existing upgrade.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/add_remaining_nodes" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterAddRemainingNodes

function New-isiUpgradeClusterArchive{
<#
.SYNOPSIS
	New Upgrade Cluster Archive

.DESCRIPTION
	Start an archive of an upgrade.

.PARAMETER clear
	If set to true the currently running upgrade will be cleared

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$clear,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/archive" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterArchive

function New-isiUpgradeClusterAssess{
<#
.SYNOPSIS
	New Upgrade Cluster Assess

.DESCRIPTION
	Start upgrade assessment on cluster.

.PARAMETER install_image_path
	The location (path) of the upgrade image which must be within /ifs.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$install_image_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/assess" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterAssess

function New-isiUpgradeClusterCommit{
<#
.SYNOPSIS
	New Upgrade Cluster Commit

.DESCRIPTION
	Commit the upgrade of a cluster.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/commit" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterCommit

function New-isiUpgradeClusterFirmwareAssess{
<#
.SYNOPSIS
	New Upgrade Cluster Firmware Assess

.DESCRIPTION
	Start firmware upgrade assessment on cluster.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/firmware/assess" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterFirmwareAssess

function New-isiUpgradeClusterFirmwareUpgrade{
<#
.SYNOPSIS
	New Upgrade Cluster Firmware Upgrade

.DESCRIPTION
	The settings necessary to start a firmware upgrade.

.PARAMETER exclude_device
	Exclude the specified devices in the firmware upgrade.

.PARAMETER exclude_type
	Include the specified device type in the firmware upgrade.

.PARAMETER include_device
	Include the specified devices in the firmware upgrade.

.PARAMETER include_type
	Include the specified device type in the firmware upgrade.

.PARAMETER nodes_to_upgrade
	The nodes scheduled for upgrade. Order in array determines queue position number. 'All' and null option will upgrade all nodes in <lnn> order.

.PARAMETER no_burn
	Do not burn the firmware.

.PARAMETER no_reboot
	Do not reboot the node after an upgrade

.PARAMETER no_verify
	Do not verify the firmware upgrade after an upgrade.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$exclude_device,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$exclude_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$include_device,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$include_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$nodes_to_upgrade,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$no_burn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$no_reboot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$no_verify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/firmware/upgrade" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterFirmwareUpgrade

function New-isiUpgradeClusterPatchAbort{
<#
.SYNOPSIS
	New Upgrade Cluster Patch Abort

.DESCRIPTION
	Abort the previous action performed by the patch system.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/patch/abort" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterPatchAbort

function New-isiUpgradeClusterPatchPatches{
<#
.SYNOPSIS
	New Upgrade Cluster Patch Patches

.DESCRIPTION
	Install a patch.

.PARAMETER location
	The path location of the patch file.

.PARAMETER patch
	The name or path of the patch to install.

.PARAMETER override
	Whether to ignore patch system validation and force the installation.

.PARAMETER rolling
	Whether to install the patch on one node at a time. Defaults to true.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$location,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$patch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$override,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$rolling,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($override){
				$queryArguments += 'override=' + $override
				$BoundParameters.Remove('override') | out-null
			}
			if ($rolling){
				$queryArguments += 'rolling=' + $rolling
				$BoundParameters.Remove('rolling') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/3/upgrade/cluster/patch/patches" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterPatchPatches

function New-isiUpgradeClusterRetryLastAction{
<#
.SYNOPSIS
	New Upgrade Cluster Retry Last Action

.DESCRIPTION
	Retry the last upgrade action, in-case the previous attempt failed.

.PARAMETER nodes
	List of the nodes or "all" where the last upgrade action can be retried.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/retry_last_action" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterRetryLastAction

function New-isiUpgradeClusterRollback{
<#
.SYNOPSIS
	New Upgrade Cluster Rollback

.DESCRIPTION
	Rollback the upgrade of a cluster.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/rollback" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterRollback

function New-isiUpgradeClusterUpgrade{
<#
.SYNOPSIS
	New Upgrade Cluster Upgrade

.DESCRIPTION
	The settings necessary to start an upgrade.

.PARAMETER install_image_path
	The location (path) of the upgrade image which must be within /ifs.

.PARAMETER nodes_to_rolling_upgrade
	The nodes (to be) scheduled for upgrade ordered by queue position number. Null if the cluster_state is 'partially upgraded' or upgrade_type is 'simultaneous'. One of the following values: [<lnn-1>, <lnn-2>, ... ], 'All', null

.PARAMETER skip_optional
	Used to indicate that the pre-upgrade check should be skipped

.PARAMETER upgrade_type
	The type of upgrade to perform. One of the following values: 'rolling', 'simultaneous'

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$install_image_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$nodes_to_rolling_upgrade,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$skip_optional,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$upgrade_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/upgrade/cluster/upgrade" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiUpgradeClusterUpgrade

function New-isiWormDomains{
<#
.SYNOPSIS
	New Worm Domains

.DESCRIPTION
	Create a WORM domain.

.PARAMETER autocommit_offset
	Specifies the autocommit time period for the domain in seconds.  After a file is in the domain without being modified for the specified time period, the file is automatically committed. If this parameter is set to null, there is no autocommit time, and files must be committed manually.

.PARAMETER default_retention
	Specifies the default amount of time, in seconds, that a file in this domain will be protected for. The default retention period is applied if no retention date is manually set on the file. This parameter can also be set to 'forever', 'use_min' (which applies the 'min_retention' option), or 'use_max' (which applies the 'max_retention' option).

.PARAMETER max_retention
	Specifies the maximum amount of time, in seconds, that a file in this domain will be protected. This setting will override the retention period of any file committed with a longer retention period. If this parameter is set to null, an infinite length retention period is set.

.PARAMETER min_retention
	Specifies the minimum amount of time, in seconds, that a file in this domain will be protected. This setting will override the retention period of any file committed with a shorter retention period. If this parameter is set to null, this minimum value is not enforced. This parameter can also be set to 'forever'.

.PARAMETER override_date
	Specifies the override retention date for the domain. If this date is later than the retention date for any committed file, the file will remain protected until the override retention date.

.PARAMETER path
	Specifies the root path of this domain. Files in this directory and all sub-directories will be protected.

.PARAMETER privileged_delete
	When this value is set to 'on', files in this domain can be deleted through the privileged delete feature. If this value is set to 'disabled', privileged file deletes are permanently disabled and cannot be turned on again.
	Valid inputs: on,off,disabled

.PARAMETER type
	Specifies whether the domain is an enterprise domain or a compliance domain. Compliance domains can not be created on enterprise clusters. Enterprise and compliance domains can be created on compliance clusters.
	Valid inputs: enterprise,compliance

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$autocommit_offset,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$default_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$max_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$min_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$override_date,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('on','off','disabled')][string]$privileged_delete,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('enterprise','compliance')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/worm/domains" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiWormDomains

function New-isiZonesv1{
<#
.SYNOPSIS
	New Zones

.DESCRIPTION
	Create a new access zone.

.PARAMETER all_auth_providers
	Enables all available authentication providers.

.PARAMETER alternate_system_provider
	Specifies an alternate system provider.

.PARAMETER audit_failure
	Specifies a list of failed operations to audit.

.PARAMETER audit_success
	Specifies a list of successful operations to audit.

.PARAMETER auth_providers
	Specifies the list of authentication providers available on this access zone.

.PARAMETER create_path
	Determines if a path is created when a path does not exist.

.PARAMETER hdfs_ambari_namenode
	Specifies the SmartConnect name of the cluster that will be used for the HDFS service.

.PARAMETER hdfs_ambari_server
	Specifies the valid hostname, FQDN, IPv4, or IPv6 string of the Ambari server.

.PARAMETER hdfs_authentication
	Specifies the authentication type for HDFS protocol.
	Valid inputs: all,simple_only,kerberos_only

.PARAMETER hdfs_root_directory
	Specifies the root directory for the HDFS protocol.

.PARAMETER home_directory_umask
	Specifies the permissions set on automatically created user home directories.

.PARAMETER ifs_restricted
	Specifies a list of users and groups that have read and write access to /ifs.

.PARAMETER map_untrusted
	Maps untrusted domains to this NetBIOS domain during authentication.

.PARAMETER name
	Specifies the access zone name.

.PARAMETER netbios_name
	Specifies the NetBIOS name.

.PARAMETER path
	Specifies the access zone base directory path.

.PARAMETER protocol_audit_enabled
	Determines if I/O auditing is enabled on this access zone.

.PARAMETER skeleton_directory
	Specifies the skeleton directory that is used for user home directories.

.PARAMETER syslog_audit_events
	Specifies a list of audit operations to forward to the syslog.

.PARAMETER syslog_forwarding_enabled
	Determines if access zone events are forwarded to the syslog.

.PARAMETER system_provider
	Specifies the system provider for the access zone.

.PARAMETER user_mapping_rules
	Specifies the current ID mapping rules.

.PARAMETER webhdfs_enabled
	True if WebHDFS is enabled on this access zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$all_auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$alternate_system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$audit_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$audit_success,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$hdfs_ambari_namenode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$hdfs_ambari_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('all','simple_only','kerberos_only')][string]$hdfs_authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$hdfs_root_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$home_directory_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$ifs_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$map_untrusted,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$netbios_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$protocol_audit_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$skeleton_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$syslog_audit_events,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$syslog_forwarding_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][array]$user_mapping_rules,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$webhdfs_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/zones" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiZonesv1
Set-Alias New-isiZones -Value New-isiZonesv1
Export-ModuleMember -Alias New-isiZones

function New-isiZonesv3{
<#
.SYNOPSIS
	New Zones

.DESCRIPTION
	Create a new access zone.

.PARAMETER alternate_system_provider
	Specifies an alternate system provider.

.PARAMETER auth_providers
	Specifies the list of authentication providers available on this access zone.

.PARAMETER cache_entry_expiry
	Specifies amount of time in seconds to cache a user/group.

.PARAMETER create_path
	Determines if a path is created when a path does not exist.

.PARAMETER force_overlap
	Allow for overlapping base path.

.PARAMETER groupnet
	Groupnet identitier

.PARAMETER home_directory_umask
	Specifies the permissions set on automatically created user home directories.

.PARAMETER ifs_restricted
	Specifies a list of users and groups that have read and write access to /ifs.

.PARAMETER map_untrusted
	Maps untrusted domains to this NetBIOS domain during authentication.

.PARAMETER name
	Specifies the access zone name.

.PARAMETER netbios_name
	Specifies the NetBIOS name.

.PARAMETER path
	Specifies the access zone base directory path.

.PARAMETER skeleton_directory
	Specifies the skeleton directory that is used for user home directories.

.PARAMETER system_provider
	Specifies the system provider for the access zone.

.PARAMETER user_mapping_rules
	Specifies the current ID mapping rules.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$alternate_system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$force_overlap,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$home_directory_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$ifs_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$map_untrusted,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$netbios_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$skeleton_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$user_mapping_rules,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/3/zones" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			return $ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiZonesv3


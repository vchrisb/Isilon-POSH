# The MIT License
#
# Copyright (c) 2015 Christopher Banck.
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

#Build using Isilon OneFS build: B_7_2_1_014(RELEASE)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


function New-isiAuditTopics{
<#
.SYNOPSIS
	New Audit Topics

.DESCRIPTION
	Create a new audit topic.

.PARAMETER max_cached_messages
	Maximum number of messages held in internal queues.

.PARAMETER name
	Audit topic name.

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
			$ISIObject.id
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

.PARAMETER provider
	Optional provider type.

.PARAMETER zone
	Optional zone.

.PARAMETER gid
	A numeric group identifier.

.PARAMETER members
	Members of the group.

.PARAMETER name
	A group name.

.PARAMETER sid
	A security identifier.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$members,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$sid,
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/groups" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
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

.PARAMETER provider
	Filter group members by provider.

.PARAMETER zone
	Filter group members by zone.

.PARAMETER id
	Serialized form (e.g. 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', 'SID:S-1-1').

.PARAMETER name
	Persona name, must be combined with type.

.PARAMETER type
	Type of persona when using name.
	Valid inputs: user,group,wellknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$group_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$group_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('user','group','wellknown')][string]$type,
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($psBoundParameters.ContainsKey('group_id')){
				$parameter1 = $group_id
				$BoundParameters.Remove('group_id') | out-null
			} else {
				$parameter1 = $group_name
				$BoundParameters.Remove('group_name') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/groups/$parameter1/members" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
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

.PARAMETER 2way
	Create a bi-directional mapping from source to target and target to source.

.PARAMETER replace
	Replace existing mappings.

.PARAMETER zone
	Optional zone.

.PARAMETER source
	Source identity.

.PARAMETER targets
	

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$2way,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$replace,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$source,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$targets,
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/mapping/identities" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject
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

.PARAMETER zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('uid','gid','sid')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($type){
				$queryArguments += 'type=' + $type
				$BoundParameters.Remove('type') | out-null
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/mapping/identities/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.identities
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthMappingIdentities

function New-isiAuthProvidersAds{
<#
.SYNOPSIS
	New Auth Providers Ads

.DESCRIPTION
	Create a new ADS provider.

.PARAMETER account
	Machine account name to use in AD. Default is the cluster name.

.PARAMETER allocate_gids
	Allocate GIDs for unmapped AD groups.

.PARAMETER allocate_uids
	Enables allocation of UIDs for unmapped AD users.

.PARAMETER assume_default_domain
	Enables lookup of unqualified user names in the primary domain.

.PARAMETER authentication
	Enables use of provider for authentication as well as identity.

.PARAMETER cache_entry_expiry
	Specifies amount of time in seconds to cache a user/group.

.PARAMETER check_online_interval
	Specifies time in seconds between provider online checks.

.PARAMETER controller_time
	The domain controllers current time.

.PARAMETER create_home_directory
	Automatically create home directory on first login.

.PARAMETER dns_domain
	The DNS search domain.  Set if DNS search domain differs.

.PARAMETER domain_offline_alerts
	Send an alert if the domain goes offline.

.PARAMETER home_directory_template
	Specifies home directory template path.

.PARAMETER ignored_trusted_domains
	Includes trusted domains when ignore_all_trusts false.

.PARAMETER ignore_all_trusts
	Ignores all trusted domains.

.PARAMETER include_trusted_domains
	Includes trusted domains when ignore_all_trusts is true.

.PARAMETER kerberos_hdfs_spn
	SPN for using Kerberized HDFS.

.PARAMETER kerberos_nfs_spn
	SPN for using Kerberized NFS.

.PARAMETER ldap_sign_and_seal
	Uses encryption and signing on LDAP requests.

.PARAMETER login_shell
	Sets login shell path.

.PARAMETER lookup_domains
	Limits user and group lookups to the specified domains.

.PARAMETER lookup_groups
	Looks up AD groups in other providers before allocating a GID.

.PARAMETER lookup_normalize_groups
	Normalizes AD group names to lowercase before lookup.

.PARAMETER lookup_normalize_users
	Normalize AD user names to lowercase before lookup.

.PARAMETER lookup_users
	Looks up AD users in other providers before allocating a UID.

.PARAMETER machine_password_changes
	Enables periodic changes of machine password for security.

.PARAMETER machine_password_lifespan
	Sets maximum age of a password in seconds.

.PARAMETER name
	Specifies Active Directory provider name.

.PARAMETER node_dc_affinity
	Specifies the domain controller to which the node should affinitize

.PARAMETER node_dc_affinity_timeout
	Specifies the timeout for the local node affinity to a domain controller

.PARAMETER nss_enumeration
	Enables the Active Directory provider to respond to getpwent and getgrent requests.

.PARAMETER organizational_unit
	The organizational unit.

.PARAMETER password
	Password used during domain join.

.PARAMETER sfu_support
	Specifies whether to support RFC 2307 attributes for Windows domain controllers.
	Valid inputs: none,rfc2307

.PARAMETER store_sfu_mappings
	Stores SFU mappings permanently in the ID mapper.

.PARAMETER user
	User name with permission to join machine to the given domain.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$controller_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$dns_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$domain_offline_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$ignored_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$ignore_all_trusts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$include_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$kerberos_hdfs_spn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$kerberos_nfs_spn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$ldap_sign_and_seal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$lookup_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$lookup_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$lookup_normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$lookup_normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$lookup_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$machine_password_changes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$machine_password_lifespan,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$node_dc_affinity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$node_dc_affinity_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$nss_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$organizational_unit,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateSet('none','rfc2307')][string]$sfu_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$store_sfu_mappings,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/ads" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersAds

function New-isiAuthProvidersFile{
<#
.SYNOPSIS
	New Auth Providers File

.DESCRIPTION
	Create a new file provider.

.PARAMETER authentication
	Enables use of provider for authentication as well as identity.

.PARAMETER cache_entry_expiry
	Specifies amount of time in seconds to cache a user/group.

.PARAMETER create_home_directory
	Automatically create home directory on first login.

.PARAMETER enabled
	Enables the file provider.

.PARAMETER enumerate_groups
	Enables provider to enumerate groups.

.PARAMETER enumerate_users
	Enables provider to enumerate users.

.PARAMETER findable_groups
	Sets list of groups that can be resolved.

.PARAMETER findable_users
	Sets list of users that can be resolved.

.PARAMETER group_domain
	Domain used to qualify groups for this provider.

.PARAMETER group_file
	Location of the file containing group information.

.PARAMETER home_directory_template
	Specifies home directory template path.

.PARAMETER listable_groups
	Specifies groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies users that can be viewed in the provider.

.PARAMETER login_shell
	Sets login shell path.

.PARAMETER modifiable_groups
	Specifies groups that can be modified in the provider.

.PARAMETER modifiable_users
	Specifies users that can be modified in the provider.

.PARAMETER name
	Specifies file provider name.

.PARAMETER netgroup_file
	Path to a netgroups replacement file.

.PARAMETER normalize_groups
	Normalizes group name to lowercase before lookup.

.PARAMETER normalize_users
	Normalizes user name to lowercase before lookup.

.PARAMETER ntlm_support
	For users with NTLM-compatible credentials, specify what NTLM versions to support.
	Valid inputs: all,v2only,none

.PARAMETER password_file
	Location of the file containing user information.

.PARAMETER provider_domain
	Specifies the provider domain.

.PARAMETER restrict_findable
	Check the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	Check the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER restrict_modifiable
	Check the provider for filtered lists of modifiable and unmodifiable users and groups.

.PARAMETER unfindable_groups
	Specifies a group that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies a group that cannot be resolved by the provider.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER unmodifiable_groups
	Specifies a group that cannot be modified by the provider.

.PARAMETER unmodifiable_users
	Specifies a user that cannot be modified by the provider.

.PARAMETER user_domain
	Domain used to qualify users for this provider.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$group_domain,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$group_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$modifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$modifiable_users,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$netgroup_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$password_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$restrict_modifiable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unmodifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$unmodifiable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/file" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersFile

function New-isiAuthProvidersKrb5{
<#
.SYNOPSIS
	New Auth Providers Krb5

.DESCRIPTION
	Create a new KRB5 provider.

.PARAMETER keytab_entries
	

.PARAMETER keytab_file
	Path to a keytab file to import

.PARAMETER manual_keying
	

.PARAMETER name
	Specifies Kerberos provider name.

.PARAMETER password
	

.PARAMETER realm
	Name of realm we are joined to

.PARAMETER user
	Name of the user to use for kadmin tasks

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$keytab_entries,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$keytab_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$manual_keying,
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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersKrb5

function New-isiAuthProvidersLdap{
<#
.SYNOPSIS
	New Auth Providers Ldap

.DESCRIPTION
	Create a new LDAP provider.

.PARAMETER alternate_security_identities_attribute
	Specifies attribute name used when searching for alternate security identities.

.PARAMETER authentication
	Enables use of provider for authentication as well as identity.

.PARAMETER balance_servers
	Makes provider connect to a random server.

.PARAMETER base_dn
	Sets root of tree in which to search identities.

.PARAMETER bind_dn
	Sets distinguished name used when binding to LDAP server.

.PARAMETER bind_mechanism
	Bind mechanism to use when connecting to an LDAP server; 'simple' is the only supported option.
	Valid inputs: simple,gssapi,digest-md5

.PARAMETER bind_password
	Sets password for distinguished name used when binding to the LDAP server.

.PARAMETER bind_timeout
	Sets timeout in seconds when binding to LDAP server.

.PARAMETER cache_entry_expiry
	Specifies amount of time in seconds to cache a user/group.

.PARAMETER certificate_authority_file
	Sets path to root certificates file.

.PARAMETER check_online_interval
	Specifies time in seconds between provider online checks.

.PARAMETER cn_attribute
	Specifies canonical name.

.PARAMETER create_home_directory
	Automatically create home directory on first login.

.PARAMETER crypt_password_attribute
	Sets hashed password value.

.PARAMETER email_attribute
	Sets the LDAP Email attribute.

.PARAMETER enabled
	Enables the LDAP provider.

.PARAMETER enumerate_groups
	Enables provider to enumerate groups.

.PARAMETER enumerate_users
	Enables provider to enumerate users.

.PARAMETER findable_groups
	Sets list of groups that can be resolved.

.PARAMETER findable_users
	Sets list of users that can be resolved.

.PARAMETER gecos_attribute
	Sets the LDAP GECOS attribute.

.PARAMETER gid_attribute
	Sets the LDAP GID attribute.

.PARAMETER group_base_dn
	Sets distinguished name of the entry at which to start LDAP searches for groups.

.PARAMETER group_domain
	Domain used to qualify groups for this provider.

.PARAMETER group_filter
	Sets LDAP filter for group objects.

.PARAMETER group_members_attribute
	Sets the LDAP Group Members attribute.

.PARAMETER group_search_scope
	Defines the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER homedir_attribute
	Sets the LDAP Homedir attribute.

.PARAMETER home_directory_template
	Specifies home directory template path.

.PARAMETER ignore_tls_errors
	Continues over secure connection even if identity checks fail.

.PARAMETER listable_groups
	Specifies groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies users that can be viewed in the provider.

.PARAMETER login_shell
	Sets login shell path.

.PARAMETER member_of_attribute
	Sets the LDAP Query Member Of attribute, which is used for reverse membership queries

.PARAMETER name
	Specifies the name of the LDAP provider.

.PARAMETER name_attribute
	Sets the LDAP UID attribute, which is used as the login name.

.PARAMETER netgroup_base_dn
	Sets distinguished name of the entry at which to start the LDAP search for netgroups.

.PARAMETER netgroup_filter
	Sets LDAP filter for netgroup objects.

.PARAMETER netgroup_members_attribute
	Sets the LDAP Netgroup Members attribute.

.PARAMETER netgroup_search_scope
	Defines the depth from the base DN to perform LDAP searches.
	Valid inputs: default,base,onelevel,subtree,children

.PARAMETER netgroup_triple_attribute
	Sets the LDAP Netgroup Triple attribute.

.PARAMETER normalize_groups
	Normalizes group name to lowercase before lookup.

.PARAMETER normalize_users
	Normalizes user name to lowercase before lookup.

.PARAMETER ntlm_support
	For users with NTLM-compatible credentials, specify what NTLM versions to support.
	Valid inputs: all,v2only,none

.PARAMETER nt_password_attribute
	Sets the LDAP NT Password attribute.

.PARAMETER provider_domain
	Specifies the provider domain.

.PARAMETER require_secure_connection
	Specifies whether to continue over non-TLS connection.

.PARAMETER restrict_findable
	Check the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	Check the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER search_scope
	Defines the default depth from the base DN to perform LDAP searches.
	Valid inputs: base,onelevel,subtree,children

.PARAMETER search_timeout
	Sets search timeout period in seconds.

.PARAMETER server_uris
	Sets server URIs.

.PARAMETER shell_attribute
	Sets the LDAP Shell attribute.

.PARAMETER uid_attribute
	Sets the LDAP UID Number attribute.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER unique_group_members_attribute
	Sets the LDAP Unique Group Members attribute.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER user_base_dn
	Sets distinguished name of the entry at which to start LDAP searches for users.

.PARAMETER user_domain
	Domain used to qualify users for this provider.

.PARAMETER user_filter
	Sets LDAP filter for user objects.

.PARAMETER user_search_scope
	Defines the depth from the base DN to perform LDAP searches.
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$certificate_authority_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$cn_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$crypt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$email_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$gecos_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$gid_attribute,
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
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/ldap" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersLdap

function New-isiAuthProvidersNis{
<#
.SYNOPSIS
	New Auth Providers Nis

.DESCRIPTION
	Create a new NIS provider.

.PARAMETER authentication
	Enables use of provider for authentication as well as identity.

.PARAMETER balance_servers
	Makes provider connect to a random server.

.PARAMETER cache_entry_expiry
	Specifies amount of time in seconds to cache a user/group.

.PARAMETER check_online_interval
	Specifies time in seconds between provider online checks.

.PARAMETER create_home_directory
	Automatically create home directory on first login.

.PARAMETER enabled
	Enables NIS provider.

.PARAMETER enumerate_groups
	Enables provider to enumerate groups.

.PARAMETER enumerate_users
	Enables provider to enumerate users.

.PARAMETER findable_groups
	Sets list of groups that can be resolved.

.PARAMETER findable_users
	Sets list of users that can be resolved.

.PARAMETER group_domain
	Domain used to qualify groups for this provider.

.PARAMETER home_directory_template
	Specifies home directory template path.

.PARAMETER hostname_lookup
	Enables host name lookups.

.PARAMETER listable_groups
	Specifies groups that can be viewed in the provider.

.PARAMETER listable_users
	Specifies users that can be viewed in the provider.

.PARAMETER login_shell
	Sets login shell path.

.PARAMETER name
	Specifies NIS provider name.

.PARAMETER nis_domain
	Specifies NIS domain name.

.PARAMETER normalize_groups
	Normalizes group name to lowercase before lookup.

.PARAMETER normalize_users
	Normalizes user name to lowercase before lookup.

.PARAMETER ntlm_support
	For users with NTLM-compatible credentials, specify what NTLM versions to support.
	Valid inputs: all,v2only,none

.PARAMETER provider_domain
	Specifies the provider domain.

.PARAMETER request_timeout
	Specifies the request timeout interval in seconds.

.PARAMETER restrict_findable
	Check the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER restrict_listable
	Check the provider for filtered lists of listable and unlistable users and groups.

.PARAMETER retry_time
	Sets timeout period in seconds after which a request will be retried.

.PARAMETER servers
	Adds a NIS server to be used by this provider.

.PARAMETER unfindable_groups
	Specifies a group that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies a group that cannot be resolved by the provider.

.PARAMETER unlistable_groups
	Specifies a group that cannot be listed by the provider.

.PARAMETER unlistable_users
	Specifies a user that cannot be listed by the provider.

.PARAMETER user_domain
	Domain used to qualify users for this provider.

.PARAMETER ypmatch_using_tcp
	Uses TCP for YP Match operations.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][array]$findable_users,
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
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/auth/providers/nis" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthProvidersNis

function New-isiAuthRoles{
<#
.SYNOPSIS
	New Auth Roles

.DESCRIPTION
	Create a new role.

.PARAMETER description
	The description of the role.

.PARAMETER members
	Users or groups that have this role.

.PARAMETER name
	The name of the role.

.PARAMETER privileges
	Privileges granted by this role.

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
			$ISIObject.id
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
	Serialized form (e.g. 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', 'SID:S-1-1').

.PARAMETER name
	Persona name, must be combined with type.

.PARAMETER type
	Type of persona when using name.
	Valid inputs: user,group,wellknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$role_id,
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
			$ISIObject.id
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
	The ID of the privilege.

.PARAMETER name
	The name of the privilege.

.PARAMETER read_only
	Whether the privilege is read-only.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$role_id,
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
			$ISIObject.id
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
	Name of the domain

.PARAMETER realm
	Name of the realm

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
			$ISIObject.domain
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
	administrative server hostname

.PARAMETER default_domain
	Default domain mapped to this realm

.PARAMETER is_default_realm
	Specify whether this realm is default

.PARAMETER kdc
	List of KDC hostnames

.PARAMETER realm
	Name of realm

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
			$ISIObject.id
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

.PARAMETER provider
	Optional provider type.

.PARAMETER zone
	Optional zone.

.PARAMETER email
	Specifies an Email address.

.PARAMETER enabled
	Auth user is enabled.

.PARAMETER expiry
	Epoch time at which the auth user will expire.

.PARAMETER gecos
	Sets GECOS value (usually full name).

.PARAMETER home_directory
	Specifies user's home directory.

.PARAMETER name
	A user name.

.PARAMETER password
	Changes user's password.

.PARAMETER password_expires
	Specifies whether the password expires.

.PARAMETER primary_group
	Specifies the primary group by name.

.PARAMETER prompt_password_change
	Prompts the user to change their password on next login.

.PARAMETER shell
	Specifies the user's shell.

.PARAMETER sid
	A security identifier.

.PARAMETER uid
	A numeric user identifier.

.PARAMETER unlock
	Unlocks the user's account if locked.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$gecos,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$home_directory,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$password_expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$primary_group,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$prompt_password_change,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$sid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$unlock,
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/users" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthUsers

function New-isiAuthUserMemberOfGroups{
<#
.SYNOPSIS
	New Auth User Member Of Groups

.DESCRIPTION
	Add the user to a group.

.PARAMETER user_id
	User user_id

.PARAMETER user_name
	User user_name

.PARAMETER provider
	Filter groups by provider.

.PARAMETER zone
	Filter groups by zone.

.PARAMETER id
	Serialized form (e.g. 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', 'SID:S-1-1').

.PARAMETER name
	Persona name, must be combined with type.

.PARAMETER type
	Type of persona when using name.
	Valid inputs: user,group,wellknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$user_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$user_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('user','group','wellknown')][string]$type,
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
				$BoundParameters.Remove('user_id') | out-null
			} else {
				$parameter1 = $user_name
				$BoundParameters.Remove('user_name') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/auth/users/$parameter1/member_of" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiAuthUserMemberOfGroups

function New-isiCloudAccounts{
<#
.SYNOPSIS
	New Cloud Accounts

.DESCRIPTION
	Create a new account.

.PARAMETER account_username
	The username required to authenticate against the cloud service

.PARAMETER enabled
	Whether or not this account should be used for cloud storage

.PARAMETER key
	A valid authentication key for connecting to the cloud

.PARAMETER name
	A unique name for this account

.PARAMETER type
	The type of cloud protocol required (e.g., 'ran', 'azure')
	Valid inputs: ran,azure

.PARAMETER uri
	A valid URI pointing to the location of the cloud storage

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$account_username,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$key,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('ran','azure')][string]$type,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$uri,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/cloud/accounts" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudAccounts

function New-isiCloudJobs{
<#
.SYNOPSIS
	New Cloud Jobs

.DESCRIPTION
	Create a new job.

.PARAMETER directories
	Directories addressed by this job

.PARAMETER files
	Filenames addressed by this job

.PARAMETER file_matching_pattern
	The file filtering logic to find files for this job. (Only applicable for 'recall' jobs)

.PARAMETER policy
	The name of an existing cloudpool policy to apply to this job. (Only applicable for 'archive' jobs)

.PARAMETER type
	The type of cloud action to be performed by this job.
	Valid inputs: archive,recall,local-garbage-collection,cloud-garbage-collection,cache-writeback,cache-on-access,cache-invalidation

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$policy,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('archive','recall','local-garbage-collection','cloud-garbage-collection','cache-writeback','cache-on-access','cache-invalidation')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/cloud/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudJobs

function New-isiCloudPools{
<#
.SYNOPSIS
	New Cloud Pools

.DESCRIPTION
	Create a new pool.

.PARAMETER accounts
	A list of valid names for the accounts in this pool

.PARAMETER description
	A brief description of this pool

.PARAMETER name
	A unique name for this pool

.PARAMETER type
	The type of cloud protocol required (e.g., 'ran', 'azure')
	Valid inputs: ran,azure

.PARAMETER vendor
	A string identifier of the cloud services vendor

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$accounts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('ran','azure')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$vendor,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/cloud/pools" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudPools

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
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/cloud/settings/encryption_key" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiCloudSettingsEncryptionKey

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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiFilepoolPolicies

function New-isiJobs{
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][object]$snaprevert_params,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/job/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiJobs

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
			$ISIObject.id
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
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiLicenses

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
			$ISIObject.id
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
	Serialized form (e.g. 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', 'SID:S-1-1').

.PARAMETER name
	Persona name, must be combined with type.

.PARAMETER type
	Type of persona when using name.
	Valid inputs: user,group,wellknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$proxyuser_id,
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
			$ISIObject.id
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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiHdfsRacks

function New-isiNfsExports{
<#
.SYNOPSIS
	New Nfs Exports

.DESCRIPTION
	Create a new NFS export.

.PARAMETER force
	If true, the export will be created even if it conflicts with another export.

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

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$max_file_size,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][object]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][object]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][object]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][object]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][object]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][object]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($force){
				$queryArguments += 'force=' + $force
				$BoundParameters.Remove('force') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/protocols/nfs/exports" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsExports

function New-isiNfsReload{
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
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsReload

function New-isiSmbShares{
<#
.SYNOPSIS
	New Smb Shares

.DESCRIPTION
	Create a new share.

.PARAMETER zone
	Zone which contains this share.

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
	Ordered list of permission modifications.

.PARAMETER run_as_root
	Allow account to run as root.

.PARAMETER strict_flush
	Handle SMB flush operations.

.PARAMETER strict_locking
	Specifies whether byte range locks contend against SMB I/O.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$allow_variable_expansion,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$auto_create_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$browsable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('all','norecurse','none')][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][ValidateSet('always','bad user','never')][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$inheritable_path_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$mangle_map,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$oplocks,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$run_as_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/protocols/smb/shares" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSmbShares

function New-isiQuotas{
<#
.SYNOPSIS
	New Quotas

.DESCRIPTION
	Create a new quota.

.PARAMETER zone
	Optional named zone to use for user and group resolution.

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
	

.PARAMETER thresholds
	

.PARAMETER thresholds_include_overhead
	If true, thresholds apply to data plus filesystem overhead required to store the data (i.e. 'physical' usage).

.PARAMETER type
	The type of quota.
	Valid inputs: directory,user,group,default-user,default-group

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$container,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enforced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$force,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$include_snapshots,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$persona,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][object]$thresholds,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$thresholds_include_overhead,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('directory','user','group','default-user','default-group')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/1/quota/quotas" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$action_email_owner,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('exceeded','denied','violated','expired')][string]$condition,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][object]$schedule,
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
			$ISIObject.id
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
			$ISIObject.id
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
			$ISIObject.id
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$action_email_owner,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('exceeded','denied','violated','expired')][string]$condition,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$schedule,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('hard','soft','advisory')][string]$threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/quota/settings/notifications" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
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
			$ISIObject.aliases
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotAliases

function New-isiSnapshotSchedules{
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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSnapshotSchedules

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/snapshot/snapshots" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$snapshot_id,
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
			$ISIObject.id
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
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolCompatibilitiesClassActive

function New-isiStoragepoolCompatibilitiesSSDActive{
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
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolCompatibilitiesSSDActive

function New-isiStoragepoolNodepools{
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$tier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/storagepool/nodepools" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolNodepools

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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiStoragepoolTiers

function New-isiSyncJobs{
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/jobs" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncJobs

function New-isiSyncPolicies{
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

.PARAMETER skip_lookup
	Skip DNS lookup of target IPs.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$skip_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][array]$source_exclude_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$source_include_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][object]$source_network,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$source_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$source_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$source_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$source_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$target_compare_initial_sync,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$target_detect_modifications,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$target_host,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$target_snapshot_alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$target_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][int]$target_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$target_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/sync/policies" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncPolicies

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
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
			$ISIObject.id
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
			$ISIObject.message
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncReportsRotate

function New-isiSyncRules{
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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncRules

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
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
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiSyncTargetPolicyCancel

function New-isiWormDomains{
<#
.SYNOPSIS
	New Worm Domains

.DESCRIPTION
	Create a WORM domain.

.PARAMETER autocommit_offset
	The autocommit time period in seconds for the domain.  After a file exists in this domain without being modified for the specified time period, the file is automatically committed the next time the file is accessed.  If null, there is no autocommit time so files must be manually committed.

.PARAMETER default_retention
	The default amount of time, in seconds, that a file in this domain will be protected for.  This default is applied to a file if it is committed to the domain before being assigned its own expiration date.  Value can also be null (expire right away), 'forever', 'use_min' (use the 'min_retention' value), or 'use_max' (use the 'max_retention' value).

.PARAMETER max_retention
	The maximum amount of time, in seconds, that a file in this domain will be protected for.  This will override the retention period of any file committed with a longer retention period.  Value can also be null (allow an infinite length retention period).

.PARAMETER min_retention
	The minimum amount of time, in seconds, that a file in this domain will be protected for.  This will override the retention period of any file committed with a shorter retention period.  Value can also be null (expire right away), or 'forever'.

.PARAMETER override_date
	Override retention date for the domain.  If this date is later than any committed file's own retention date, that file will remain protected beyond its own retention date until this date.

.PARAMETER path
	Root path of this domain.  Files in this directory and all sub-directories will be protected.

.PARAMETER privileged_delete
	If 'on', files in this domain can be deleted using the privileged delete feature.  Otherwise, they can't be deleted even with privileged delete.  If 'disabled', privileged file deletes are permanently disabled and cannot be turned back on again.
	Valid inputs: on,off,disabled

.PARAMETER type
	Whether this is an enterprise domain or this is a compliance domain. Compliance domains may not be created on enterprise clusters. Enterprise and compliance domains may be created on compliance clusters.
	Valid inputs: enterprise,compliance

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$autocommit_offset,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$default_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$max_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$min_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$override_date,
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
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiWormDomains

function New-isiZones{
<#
.SYNOPSIS
	New Zones

.DESCRIPTION
	Create a new access zone.

.PARAMETER all_auth_providers
	Use all authentication providers available.

.PARAMETER alternate_system_provider
	Alternate system provider.

.PARAMETER audit_failure
	List of failed operations to audit.

.PARAMETER audit_success
	List of successful operations to audit.

.PARAMETER auth_providers
	List of authentication providers used on this zone.

.PARAMETER cache_size
	Specifies the maximum size of zone in-memory cache.

.PARAMETER create_path
	Create path if it does not exist.

.PARAMETER hdfs_ambari_namenode
	The SmartConnect name of this cluster that will be used for the HDFS service.

.PARAMETER hdfs_ambari_server
	A valid hostname, FQDN, IPv4, or IPv6 string of the Ambari server.

.PARAMETER hdfs_authentication
	Authentication type for HDFS protocol.
	Valid inputs: all,simple_only,kerberos_only

.PARAMETER hdfs_root_directory
	Root directory for HDFS protocol.

.PARAMETER home_directory_umask
	Permissions set on auto-created user home directories.

.PARAMETER ifs_restricted
	User restrictions for this zone.

.PARAMETER map_untrusted
	Maps untrusted domains to this NetBIOS domain during authentication.

.PARAMETER name
	Zone name.

.PARAMETER netbios_name
	NetBIOS name.

.PARAMETER path
	zone path.

.PARAMETER protocol_audit_enabled
	Indicates whether I/O auditing is set on this zone.

.PARAMETER skeleton_directory
	Skeleton directory for user home directories.

.PARAMETER syslog_audit_events
	List of audit operations to forward to syslog.

.PARAMETER syslog_forwarding_enabled
	Enable syslog forwarding of zone audit events.

.PARAMETER system_provider
	System provider.

.PARAMETER user_mapping_rules
	Current ID mapping rules.

.PARAMETER webhdfs_enabled
	Indicates whether WebHDFS is enabled on this zone.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$cache_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$hdfs_ambari_namenode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$hdfs_ambari_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('all','simple_only','kerberos_only')][string]$hdfs_authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$hdfs_root_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$home_directory_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$ifs_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$map_untrusted,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$netbios_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$protocol_audit_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$skeleton_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$syslog_audit_events,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$syslog_forwarding_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$user_mapping_rules,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$webhdfs_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$ISIObject = Send-isiAPI -Method POST -Resource "/platform/1/zones" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiZones

function New-isiNfsAliasesV2{
<#
.SYNOPSIS
	New Nfs Aliases

.DESCRIPTION
	Create a new NFS alias.

.PARAMETER zone
	Access zone

.PARAMETER health
	Describes whether and why the alias is unusable

.PARAMETER name
	The name by which the alias can be referenced

.PARAMETER path
	The path to which the alias points

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$health,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/2/protocols/nfs/aliases" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsAliasesV2

function New-isiNfsExportsV2{
<#
.SYNOPSIS
	New Nfs Exports

.DESCRIPTION
	Create a new NFS export.

.PARAMETER force
	If true, the export will be created even if it conflicts with another export.

.PARAMETER zone
	Access zone

.PARAMETER all_dirs
	If true, all directories under the specified paths are mountable.

.PARAMETER block_size
	The block size returned by the NFS STATFS procedure.

.PARAMETER can_set_time
	If true, the client may  set file  times using the NFS SETATTR request.  This  option is advisory and the server always behaves as if it is true.

.PARAMETER case_insensitive
	If true, the server will report that it ignores case for file names.

.PARAMETER case_preserving
	If true, the server will report that it always preserves case for file names.

.PARAMETER chown_restricted
	If true, the server will report that only the superuser may change file ownership.

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

.PARAMETER link_max
	The reported maximum number of links to a file.

.PARAMETER map_all
	The user and groups that non-root clients are mapped to.

.PARAMETER map_failure
	The user and groups that clients are mapped to should auth fail.

.PARAMETER map_full
	If true, user mappings queries the OneFS user database.  If false, only local authentication is queried.

.PARAMETER map_lookup_uid
	If true, incoming UIDs are mapped to users in the OneFS user database.  If false, incoming UIDs are applied directly to file operations.

.PARAMETER map_non_root
	The user and groups that nonroot clients are mapped to.

.PARAMETER map_retry
	Determines whether lookups for users specified in map_all, map_root or map_nonroot are retried if the look fails.

.PARAMETER map_root
	The user and groups that root clients are mapped to.

.PARAMETER max_file_size
	The maximum file size in the export.

.PARAMETER name_max_size
	The reported maximum length of a file name.

.PARAMETER no_truncate
	If true, report that too-long file names result in an error

.PARAMETER paths
	The paths under /ifs that are exported.

.PARAMETER readdirplus
	If true, readdirplus requests are enabled.

.PARAMETER readdirplus_prefetch
	This field is deprecated and does not do anything.

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

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$case_insensitive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$case_preserving,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$chown_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$link_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][object]$map_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][object]$map_non_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$name_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$no_truncate,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][object]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][object]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][object]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][object]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][object]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][object]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=49)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($force){
				$queryArguments += 'force=' + $force
				$BoundParameters.Remove('force') | out-null
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters.Remove('zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method POST -Resource ("/platform/2/protocols/nfs/exports" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			$ISIObject.id
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsExportsV2

function New-isiNfsReloadV2{
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
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function New-isiNfsReloadV2


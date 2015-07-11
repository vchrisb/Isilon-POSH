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


function Set-isiAuditSettings{
<#
.SYNOPSIS
	Set Audit Settings

.DESCRIPTION
	Modify the auditing global settings.  All input fields are optional, but one or more must be supplied.

.PARAMETER audited_zones
	 Zones that are audited when protocol auditing is enabled.

.PARAMETER cee_log_time
	 Sets audit CEE forwarder to forward events past a specified date in 'Topic@YYYY-MM-DD HH:MM:SS' format

.PARAMETER cee_server_uris
	 URIs of backend CEE servers to which to send audit logs

.PARAMETER config_auditing_enabled
	 Enables/disables PAPI configuration audit

.PARAMETER config_syslog_enabled
	 Enables/disables config audit syslog forwarding.

.PARAMETER hostname
	 Hostname reported in protocol events from this cluster

.PARAMETER protocol_auditing_enabled
	 Enables/disables auditing of I/O requests

.PARAMETER syslog_log_time
	 Sets audit syslog forwarder to forward events past a specified date in 'Topic@YYYY-MM-DD HH:MM:SS' format

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$audited_zones,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$cee_log_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$cee_server_uris,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$config_auditing_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$config_syslog_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$hostname,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$protocol_auditing_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$syslog_log_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuditSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/audit/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuditSettings

function Set-isiAuditTopic{
<#
.SYNOPSIS
	Set Audit Topic

.DESCRIPTION
	Modify the audit topic.

.PARAMETER id
	Topic id

.PARAMETER name
	Topic name

.PARAMETER new_id
	Audit topic name.

.PARAMETER max_cached_messages
	Maximum number of messages held in internal queues.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$max_cached_messages,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_id){
				$BoundParameters.Remove('new_id') | out-null
				$BoundParameters.Add('id',$new_id)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuditTopic')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/audit/topics/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuditTopic

function Set-isiAuthGroup{
<#
.SYNOPSIS
	Set Auth Group

.DESCRIPTION
	Modify the group.

.PARAMETER id
	Group id

.PARAMETER name
	Group name

.PARAMETER provider
	Optional provider type.

.PARAMETER zone
	Optional zone.

.PARAMETER gid
	A numeric group identifier.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters = $BoundParameters.Remove('$provider')
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthGroup')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/groups/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthGroup

function Set-isiAuthMappingUsersRules{
<#
.SYNOPSIS
	Set Auth Mapping Users Rules

.DESCRIPTION
	Modify the user mapping rules.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=0)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthMappingUsersRules')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/mapping/users/rules" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthMappingUsersRules

function Set-isiAuthProviderAds{
<#
.SYNOPSIS
	Set Auth Provider Ads

.DESCRIPTION
	Modify the ADS provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

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

.PARAMETER domain_controller
	A preferred domain controller to which the authentication service should send requests

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

.PARAMETER node_dc_affinity
	 Specifies the domain controller to which the node should affinitize

.PARAMETER node_dc_affinity_timeout
	 Specifies the timeout for the local node affinity to a domain controller

.PARAMETER nss_enumeration
	 Enables the Active Directory provider to respond to getpwent and getgrent requests.

.PARAMETER reset_schannel
	Reset the secure channel to the primary domain.

.PARAMETER sfu_support
	 Specifies whether to support RFC 2307 attributes for Windows domain controllers.

.PARAMETER store_sfu_mappings
	 Stores SFU mappings permanently in the ID mapper.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allocate_gids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allocate_uids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$assume_default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$controller_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$domain_controller,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$domain_offline_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$ignored_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$ignore_all_trusts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$include_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$ldap_sign_and_seal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$lookup_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$lookup_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$lookup_normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$lookup_normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$lookup_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$machine_password_changes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$machine_password_lifespan,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$node_dc_affinity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$node_dc_affinity_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$nss_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$reset_schannel,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$sfu_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$store_sfu_mappings,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=30)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderAds')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/ads/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderAds

function Set-isiAuthProviderFile{
<#
.SYNOPSIS
	Set Auth Provider File

.DESCRIPTION
	Modify the file provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

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

.PARAMETER new_name
	Specifies file provider name.

.PARAMETER netgroup_file
	 Path to a netgroups replacement file.

.PARAMETER normalize_groups
	 Normalizes group name to lowercase before lookup.

.PARAMETER normalize_users
	 Normalizes user name to lowercase before lookup.

.PARAMETER ntlm_support
	 For users with NTLM-compatible credentials, specify what NTLM versions to support.

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$group_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$modifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][array]$modifiable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$netgroup_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$password_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$restrict_modifiable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$unmodifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][array]$unmodifiable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=34)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderFile')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/file/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderFile

function Set-isiAuthProviderKrb5{
<#
.SYNOPSIS
	Set Auth Provider Krb5

.DESCRIPTION
	Modify the KRB5 provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER keytab_entries
	Service principal names to register

.PARAMETER keytab_file
	Path to a keytab file to import

.PARAMETER manual_keying
	Indicates keys are managed manually rather than with kadmin

.PARAMETER new_name
	Specifies Kerberos provider name.

.PARAMETER password
	

.PARAMETER realm
	Name of realm we are joined to

.PARAMETER status
	The status of the provider.

.PARAMETER user
	Name of the user to use for kadmin tasks

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$keytab_entries,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$keytab_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$manual_keying,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderKrb5')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/krb5/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderKrb5

function Set-isiAuthProviderLdap{
<#
.SYNOPSIS
	Set Auth Provider Ldap

.DESCRIPTION
	Modify the LDAP provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

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

.PARAMETER new_name
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

.PARAMETER netgroup_triple_attribute
	 Sets the LDAP Netgroup Triple attribute.

.PARAMETER normalize_groups
	 Normalizes group name to lowercase before lookup.

.PARAMETER normalize_users
	 Normalizes user name to lowercase before lookup.

.PARAMETER ntlm_support
	 For users with NTLM-compatible credentials, specify what NTLM versions to support.

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$alternate_security_identities_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$bind_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$bind_mechanism,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$bind_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$bind_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$certificate_authority_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$cn_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$crypt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$email_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$gecos_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$gid_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$group_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][string]$group_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$group_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$group_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$homedir_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$ignore_tls_errors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$member_of_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][string]$name_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$netgroup_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$netgroup_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][string]$netgroup_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][string]$netgroup_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][string]$netgroup_triple_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][string]$nt_password_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][bool]$require_secure_connection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=49)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=50)][string]$search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=51)][int]$search_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=52)][array]$server_uris,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=53)][string]$shell_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=54)][string]$uid_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=55)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=56)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=57)][string]$unique_group_members_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=58)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=59)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=60)][string]$user_base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=61)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=62)][string]$user_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=63)][string]$user_search_scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=64)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=65)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderLdap')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/ldap/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderLdap

function Set-isiAuthProviderLocal{
<#
.SYNOPSIS
	Set Auth Provider Local

.DESCRIPTION
	Modify the local provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER authentication
	 Enables use of provider for authentication as well as identity.

.PARAMETER create_home_directory
	 Automatically create home directory on first login.

.PARAMETER home_directory_template
	 Specifies home directory template path.

.PARAMETER lockout_duration
	 Sets length of time in seconds that an account will be inaccessible after multiple failed login attempts.

.PARAMETER lockout_threshold
	 Sets the number of failed login attempts necessary for an account to be locked out.

.PARAMETER lockout_window
	 Sets the time in seconds in which lockout_threshold failed attempts must be made for an account to be locked out.

.PARAMETER login_shell
	 Sets login shell path.

.PARAMETER machine_name
	 Specifies domain used to qualify user and group names for this provider.

.PARAMETER max_password_age
	 Sets maximum password age in seconds.

.PARAMETER min_password_age
	 Sets minimum password age in seconds.

.PARAMETER min_password_length
	 Sets minimum password length.

.PARAMETER new_name
	Specifies local provider name.

.PARAMETER password_complexity
	 List of cases required in a password. Options are lowercase, uppercase, numeric and symbol

.PARAMETER password_history_length
	 The number of previous passwords to store.

.PARAMETER password_prompt_time
	 Specifies time in seconds remaining before prompting for password change.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$lockout_duration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$lockout_threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$lockout_window,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$machine_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$max_password_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$min_password_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$min_password_length,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$password_complexity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$password_history_length,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$password_prompt_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=16)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderLocal')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/local/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderLocal

function Set-isiAuthProviderNis{
<#
.SYNOPSIS
	Set Auth Provider Nis

.DESCRIPTION
	Modify the NIS provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

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

.PARAMETER new_name
	Specifies NIS provider name.

.PARAMETER nis_domain
	 Specifies NIS domain name.

.PARAMETER normalize_groups
	 Normalizes group name to lowercase before lookup.

.PARAMETER normalize_users
	 Normalizes user name to lowercase before lookup.

.PARAMETER ntlm_support
	 For users with NTLM-compatible credentials, specify what NTLM versions to support.

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$hostname_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$nis_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$request_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$retry_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][bool]$ypmatch_using_tcp,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=34)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderNis')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/nis/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderNis

function Set-isiAuthRole{
<#
.SYNOPSIS
	Set Auth Role

.DESCRIPTION
	Modify the role.

.PARAMETER id
	Role id

.PARAMETER name
	Role name

.PARAMETER description
	The description of the role.

.PARAMETER members
	Users or groups that have this role.

.PARAMETER new_name
	The name of the role.

.PARAMETER privileges
	Privileges granted by this role.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$members,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$privileges,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthRole')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/roles/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthRole

function Set-isiAuthSettingsGlobal{
<#
.SYNOPSIS
	Set Auth Settings Global

.DESCRIPTION
	Modify the global settings.

.PARAMETER zone
	Zone which contains any per-zone settings.

.PARAMETER alloc_retries
	 Sets number of times to retry an ID allocation before failing.

.PARAMETER cache_cred_lifetime
	 Sets length of time in seconds to cache credential responses from the ID mapper.

.PARAMETER cache_id_lifetime
	 Sets length of time in seconds to cache ID responses from the ID mapper.

.PARAMETER gid_range_enabled
	 Enables use of a fixed range for allocating GIDs.

.PARAMETER gid_range_max
	 Specifies ending number for allocating GIDs.

.PARAMETER gid_range_min
	 Specifies starting number for allocating GIDs.

.PARAMETER gid_range_next
	 Specifies the next GID to be allocated.

.PARAMETER group_uid
	 

.PARAMETER load_providers
	 

.PARAMETER min_mapped_rid
	 

.PARAMETER null_gid
	 

.PARAMETER null_uid
	 

.PARAMETER on_disk_identity
	 Specifies type of identity stored on disk.

.PARAMETER rpc_block_time
	 

.PARAMETER rpc_max_requests
	 

.PARAMETER rpc_timeout
	 

.PARAMETER send_ntlmv2
	 Specifies whether to send NTLMv2 responses.

.PARAMETER space_replacement
	 Sets space replacement.

.PARAMETER system_gid_threshold
	 

.PARAMETER system_uid_threshold
	 

.PARAMETER uid_range_enabled
	 Uses a fixed range for allocating UIDs.

.PARAMETER uid_range_max
	 Specifies ending number for allocating UIDs.

.PARAMETER uid_range_min
	 Specifies starting number for allocating UIDs.

.PARAMETER uid_range_next
	 Specifies the next UID to be allocated.

.PARAMETER unknown_gid
	 Specifies GID to use for the unknown (anonymous) group.

.PARAMETER unknown_uid
	 Specifies UID to use for the unknown (anonymous) user.

.PARAMETER workgroup
	 Sets NetBIOS workgroup/domain.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$alloc_retries,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$cache_cred_lifetime,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$cache_id_lifetime,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$gid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$gid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$gid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$gid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$group_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][array]$load_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$min_mapped_rid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$null_gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$null_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$on_disk_identity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$rpc_block_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$rpc_max_requests,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$rpc_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$send_ntlmv2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$space_replacement,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$system_gid_threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$system_uid_threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$uid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$uid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$uid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$uid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$unknown_gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$unknown_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$workgroup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=28)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsGlobal')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/settings/global" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthSettingsGlobal

function Set-isiAuthSettingsKrb5Defaults{
<#
.SYNOPSIS
	Set Auth Settings Krb5 Defaults

.DESCRIPTION
	Modify the krb5 settings.

.PARAMETER always_send_preauth
	 Always attempt to preauth to controller

.PARAMETER default_realm
	 Realm to use for unqualified names

.PARAMETER dns_lookup_kdc
	 Use DNS to find KDCs

.PARAMETER dns_lookup_realm
	 Use DNS to find realm names

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$always_send_preauth,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$default_realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$dns_lookup_kdc,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$dns_lookup_realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsKrb5Defaults')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/settings/krb5/defaults" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthSettingsKrb5Defaults

function Set-isiAuthSettingsKrb5Domain{
<#
.SYNOPSIS
	Set Auth Settings Krb5 Domain

.DESCRIPTION
	Modify the krb5 domain settings.

.PARAMETER id
	Domain id

.PARAMETER name
	Domain name

.PARAMETER domain
	Name of the domain

.PARAMETER realm
	Name of the realm

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsKrb5Domain')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/settings/krb5/domains/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthSettingsKrb5Domain

function Set-isiAuthSettingsKrb5Realm{
<#
.SYNOPSIS
	Set Auth Settings Krb5 Realm

.DESCRIPTION
	Modify the krb5 realm settings.

.PARAMETER id
	Realm id

.PARAMETER name
	Realm name

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$admin_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$is_default_realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$kdc,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsKrb5Realm')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/settings/krb5/realms/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthSettingsKrb5Realm

function Set-isiAuthSettingsMapping{
<#
.SYNOPSIS
	Set Auth Settings Mapping

.DESCRIPTION
	Modify the mapping settings.

.PARAMETER zone
	Access zone which contains mapping settings.

.PARAMETER gid_range_enabled
	 Enables use of a fixed range for allocating GIDs.

.PARAMETER gid_range_max
	 Specifies ending number for allocating GIDs.

.PARAMETER gid_range_min
	 Specifies starting number for allocating GIDs.

.PARAMETER gid_range_next
	 Specifies the next GID to be allocated.

.PARAMETER uid_range_enabled
	 Uses a fixed range for allocating UIDs.

.PARAMETER uid_range_max
	 Specifies ending number for allocating UIDs.

.PARAMETER uid_range_min
	 Specifies starting number for allocating UIDs.

.PARAMETER uid_range_next
	 Specifies the next UID to be allocated.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$gid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$gid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$gid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$gid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$uid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$uid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$uid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$uid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
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
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsMapping')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/settings/mapping" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthSettingsMapping

function Set-isiAuthUser{
<#
.SYNOPSIS
	Set Auth User

.DESCRIPTION
	Modify the user.

.PARAMETER id
	User id

.PARAMETER name
	User name

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

.PARAMETER password
	Changes user's password.

.PARAMETER password_expires
	Specifies whether the password expires.

.PARAMETER primary_group
	A persona consists of either a 'type' and 'name' or a 'ID'.

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$gecos,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$password_expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$primary_group,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$prompt_password_change,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$sid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$unlock,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=16)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
				$BoundParameters = $BoundParameters.Remove('$provider')
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthUser')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/users/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthUser

function Set-isiAuthUserPassword{
<#
.SYNOPSIS
	Set Auth User Change Password

.DESCRIPTION
	Change the user's password.

.PARAMETER id
	User id

.PARAMETER name
	User name

.PARAMETER new_password
	Specifies user's new password

.PARAMETER old_password
	User's expired password

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_password,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$old_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthUserPassword')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/users/$parameter1/change_password" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthUserPassword

function Set-isiCloudAccount{
<#
.SYNOPSIS
	Set Cloud Account

.DESCRIPTION
	Modify cloud account.  All fields are optional, but one or more must be supplied.

.PARAMETER id
	Account id

.PARAMETER name
	Account name

.PARAMETER account_username
	The username required to authenticate against the cloud service

.PARAMETER enabled
	Whether or not this account should be used for cloud storage

.PARAMETER key
	A valid authentication key for connecting to the cloud

.PARAMETER new_name
	A unique name for this account

.PARAMETER uri
	A valid URI pointing to the location of the cloud storage

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$account_username,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$uri,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudAccount')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/cloud/accounts/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudAccount

function Set-isiCloudJob{
<#
.SYNOPSIS
	Set Cloud Job

.DESCRIPTION
	Modify a running cloudpool job.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

.PARAMETER state
	The current state of the job

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudJob')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/cloud/jobs/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudJob

function Set-isiCloudPool{
<#
.SYNOPSIS
	Set Cloud Pool

.DESCRIPTION
	Modify a cloud pool.  All fields are optional, but one or more must be supplied.

.PARAMETER id
	Pool id

.PARAMETER name
	Pool name

.PARAMETER accounts
	A list of valid names for the accounts in this pool

.PARAMETER description
	A brief description of this pool

.PARAMETER new_name
	A unique name for this pool

.PARAMETER vendor
	A string identifier of the cloud services vendor

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$accounts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$vendor,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudPool')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/cloud/pools/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudPool

function Set-isiCloudSettings{
<#
.SYNOPSIS
	Set Cloud Settings

.DESCRIPTION
	Modify one or more settings.

.PARAMETER archive_snapshot_files
	Whether files which have had a snapshot taken should be moved to the cloud.

.PARAMETER available_cluster_guids
	A list of guids for clusters which have used this cluster for cloud storage.

.PARAMETER cloud_policy_defaults
	The default filepool policy values for cloud pools.

.PARAMETER cluster_access
	A list of guids for which this cluster has ownership of cloud storage.

.PARAMETER max_retries_archive
	The maximum number of times to retry an archive operation before failing.

.PARAMETER max_retries_cache_invalidation
	The maximum number of times to retry a cache invalidation operation before failing.

.PARAMETER max_retries_cloud_garbage_collection
	The maximum number of times to retry cloud garbage collection before failing.

.PARAMETER max_retries_local_garbage_collection
	The maximum number of times to retry local garbage collection before failing.

.PARAMETER max_retries_read_ahead
	The maximum number of times to retry a read ahead operation before failing.

.PARAMETER max_retries_recall
	The maximum number of times to retry a recall operation before failing.

.PARAMETER max_retries_writeback
	The maximum number of times to retry a writeback operation before failing.

.PARAMETER retry_coefficient_archive
	Coefficients in the quadratic function for determining the rest period between successive archive attempts.

.PARAMETER retry_coefficient_cache_invalidation
	Coefficients in the quadratic function for determining the rest period between successive cache invalidation attempts.

.PARAMETER retry_coefficient_cloud_garbage_collection
	Coefficients in the quadratic function for determining the rest period between successive cloud garbage collection attempts.

.PARAMETER retry_coefficient_local_garbage_collection
	Coefficients in the quadratic function for determining the rest period between successive local garbage collection attempts.

.PARAMETER retry_coefficient_read_ahead
	Coefficients in the quadratic function for determining the rest period between successive read ahead attempts.

.PARAMETER retry_coefficient_recall
	Coefficients in the quadratic function for determining the rest period between successive recall attempts.

.PARAMETER retry_coefficient_writeback
	Coefficients in the quadratic function for determining the rest period between successive writeback attempts.

.PARAMETER sleep_timeout_archive
	Amount of time to wait between successive file archive operations.

.PARAMETER sleep_timeout_cache_invalidation
	Amount of time to wait between successive file cache_invalidation operations.

.PARAMETER sleep_timeout_cloud_garbage_collection
	Amount of time to wait between successive file cloud garbage collection operations.

.PARAMETER sleep_timeout_local_garbage_collection
	Amount of time to wait between successive file local garbage collection operations.

.PARAMETER sleep_timeout_read_ahead
	Amount of time to wait between successive file read ahead operations.

.PARAMETER sleep_timeout_recall
	Amount of time to wait between successive file recall operations.

.PARAMETER sleep_timeout_writeback
	Amount of time to wait between successive file writeback operations.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$archive_snapshot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$available_cluster_guids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$cloud_policy_defaults,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$cluster_access,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$max_retries_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$max_retries_cache_invalidation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$max_retries_cloud_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$max_retries_local_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$max_retries_read_ahead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$max_retries_recall,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$max_retries_writeback,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$retry_coefficient_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$retry_coefficient_cache_invalidation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$retry_coefficient_cloud_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$retry_coefficient_local_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$retry_coefficient_read_ahead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$retry_coefficient_recall,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$retry_coefficient_writeback,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][object]$sleep_timeout_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][object]$sleep_timeout_cache_invalidation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][object]$sleep_timeout_cloud_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][object]$sleep_timeout_local_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][object]$sleep_timeout_read_ahead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][object]$sleep_timeout_recall,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][object]$sleep_timeout_writeback,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=25)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/cloud/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudSettings

function Set-isiDedupeSettings{
<#
.SYNOPSIS
	Set Dedupe Settings

.DESCRIPTION
	Modify the dedupe settings. All input fields are optional, but one or more must be supplied.

.PARAMETER assess_paths
	The paths that will be assessed.

.PARAMETER paths
	The paths that will be deduped.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$assess_paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiDedupeSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/dedupe/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiDedupeSettings

function Set-isiFilepoolDefaultPolicy{
<#
.SYNOPSIS
	Set Filepool Default Policy

.DESCRIPTION
	Set default file pool policy.

.PARAMETER actions
	

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$actions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFilepoolDefaultPolicy')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/filepool/default-policy" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFilepoolDefaultPolicy

function Set-isiFilepoolPolicy{
<#
.SYNOPSIS
	Set Filepool Policy

.DESCRIPTION
	Modify file pool policy. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER actions
	A list of actions to be taken for matching files

.PARAMETER apply_order
	The order in which this policy should be applied (relative to other policies)

.PARAMETER description
	A description for this policy

.PARAMETER file_matching_pattern
	The file matching rules for this policy

.PARAMETER new_name
	A unique name for this policy

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$actions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$apply_order,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFilepoolPolicy')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/filepool/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFilepoolPolicy

function Set-isiFilesystemAccessTime{
<#
.SYNOPSIS
	Set Filesystem Access Time

.DESCRIPTION
	Set settings for access time.

.PARAMETER enabled
	Enable access time tracking.

.PARAMETER precision
	Access time tracked on each cluster file accurate to this number of seconds.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$precision,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFilesystemAccessTime')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/filesystem/settings/access-time" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFilesystemAccessTime

function Set-isiFilesystemCharacterEncoding{
<#
.SYNOPSIS
	Set Filesystem Character Encoding

.DESCRIPTION
	Set current character encoding.

.PARAMETER current_encoding
	Current character encoding.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$current_encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFilesystemCharacterEncoding')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/filesystem/settings/character-encodings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFilesystemCharacterEncoding

function Set-isiFsaResult{
<#
.SYNOPSIS
	Set Fsa Result

.DESCRIPTION
	Modify result set. Only the pinned property can be changed at this time.

.PARAMETER id
	Result id

.PARAMETER name
	Result name

.PARAMETER pinned
	True if the result is pinned to prevent automatic removal.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$pinned,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFsaResult')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/fsa/results/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFsaResult

function Set-isiFsaSettings{
<#
.SYNOPSIS
	Set Fsa Settings

.DESCRIPTION
	Modify one or more settings.

.PARAMETER default_template
	 Name of question template to use for new FSA jobs.

.PARAMETER disk_usage_depth
	 Maximum directory depth used for disk_usage question if not specified in the question.

.PARAMETER max_age
	 Maximum age of non-pinned results in seconds.

.PARAMETER max_count
	 Maximum number of non-pinned result sets to keep.

.PARAMETER squash_depth
	 Squash depth to use for squash binning questions if not specified in the question.

.PARAMETER top_n_max
	 Maximum number of items in a Top-N question result if not specified in the question.

.PARAMETER use_snapshot
	 If true, use a snapshot for consistency, otherwise analyze head.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$default_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$disk_usage_depth,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$squash_depth,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$top_n_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$use_snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFsaSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/fsa/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFsaSettings

function Set-isiJob{
<#
.SYNOPSIS
	Set Job

.DESCRIPTION
	Modify a running or paused job instance.  All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

.PARAMETER policy
	Impact policy of this job instance.

.PARAMETER priority
	Priority of this job instance; lower numbers preempt higher numbers.

.PARAMETER state
	Desired new state of this job instance.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiJob')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/job/jobs/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiJob

function Set-isiJobPolicy{
<#
.SYNOPSIS
	Set Job Policy

.DESCRIPTION
	Modify a job impact policy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER description
	A helpful human-readable description of the impact policy.

.PARAMETER intervals
	

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$intervals,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiJobPolicy')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/job/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiJobPolicy

function Set-isiJobType{
<#
.SYNOPSIS
	Set Job Type

.DESCRIPTION
	Modify the job type.  All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Type id

.PARAMETER name
	Type name

.PARAMETER enabled
	Whether the job type is enabled and able to run.

.PARAMETER policy
	Default impact policy of this job type.

.PARAMETER priority
	Default priority of this job type; lower numbers preempt higher numbers.

.PARAMETER schedule
	The schedule on which this job type is queued, if any.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiJobType')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/job/types/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiJobType

function Set-isiHdfsProxyUser{
<#
.SYNOPSIS
	Set Hdfs Proxyuser

.DESCRIPTION
	Create a new HDFS proxyuser.

.PARAMETER id
	Proxyuser id

.PARAMETER name
	Proxyuser name

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsProxyUser')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsProxyUser

function Set-isiHdfsProxyUserMember{
<#
.SYNOPSIS
	Set Hdfs Proxyuser Member

.DESCRIPTION
	Create a new HDFS proxyuser.

.PARAMETER proxyuser_id
	Proxyuser proxyuser_id

.PARAMETER proxyuser_name
	Proxyuser proxyuser_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$proxyuser_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$proxyuser_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($proxyuser_id){
				$parameter1 = $proxyuser_id
				$BoundParameters.Remove('proxyuser_id') | out-null
			} else {
				$parameter1 = $proxyuser_name
				$BoundParameters.Remove('proxyuser_name') | out-null
			}
			if ($id){
				$parameter2 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter2 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsProxyUserMember')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1/members/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsProxyUserMember

function Set-isiHdfsRack{
<#
.SYNOPSIS
	Set Hdfs Rack

.DESCRIPTION
	Modify the HDFS rack

.PARAMETER id
	Rack id

.PARAMETER name
	Rack name

.PARAMETER client_ip_ranges
	Array of IP ranges. Clients from one of these IP ranges are served by corresponding nodes from ip_pools array.

.PARAMETER ip_pools
	Array of IP pool names to use for serving clients from client_ip_ranges.

.PARAMETER new_name
	Name of the rack

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$client_ip_ranges,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$ip_pools,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsRack')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/hdfs/racks/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsRack

function Set-isiHdfsSettings{
<#
.SYNOPSIS
	Set Hdfs Settings

.DESCRIPTION
	Modify HDFS properties.

.PARAMETER default_block_size
	Block size (size=2**value) reported by HDFS server.

.PARAMETER default_checksum_type
	Checksum type reported by HDFS server.

.PARAMETER server_log_level
	Log level for HDFS daemon.

.PARAMETER server_threads
	Number of worker threads for HDFS daemon.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$default_block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$default_checksum_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$server_log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$server_threads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/hdfs/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsSettings

function Set-isiNfsExport{
<#
.SYNOPSIS
	Set Nfs Export

.DESCRIPTION
	Modify the export. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	 id

.PARAMETER enforce
	If true, the export will be updated even if that change conflicts with another export.

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
	User and group mapping.

.PARAMETER map_full
	 If true, user mappings queries the OneFS user database.  If false, only local authentication is queried.

.PARAMETER map_lookup_uid
	 If true, incoming UIDs are mapped to users in the OneFS user database.  If false, incoming UIDs are applied directly to file operations.

.PARAMETER map_retry
	 Determines whether lookups for users specified in map_all or map_root are retried if the look fails.

.PARAMETER map_root
	User and group mapping.

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
	The synchronization type.

.PARAMETER write_datasync_reply
	The synchronization type.

.PARAMETER write_filesync_action
	The synchronization type.

.PARAMETER write_filesync_reply
	The synchronization type.

.PARAMETER write_transfer_max_size
	 The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	 The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	 The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The synchronization type.

.PARAMETER write_unstable_reply
	The synchronization type.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=41)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$parameter1 = $id
			$BoundParameters.Remove('id') | out-null
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
				$BoundParameters = $BoundParameters.Remove('$enforce')
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsExport')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/protocols/nfs/exports/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsExport

function Set-isiNfsSettingsExport{
<#
.SYNOPSIS
	Set Nfs Settings Export

.DESCRIPTION
	Modify the default values for NFS exports. All input fields are optional, but one or more must be supplied.

.PARAMETER all_dirs
	 If true, all directories under the specified paths are mountable.

.PARAMETER block_size
	 The block size returned by the NFS STATFS procedure.

.PARAMETER can_set_time
	 If true, the client may  set file  times using the NFS SETATTR request.  This  option is advisory and the server always behaves as if it is true.

.PARAMETER commit_asynchronous
	 If true, allows NFS  commit  requests to  execute asynchronously.

.PARAMETER directory_transfer_size
	 The preferred size for directory read operations.  This option is advisory.

.PARAMETER encoding
	 The character encoding of clients connecting to the export.

.PARAMETER map_all
	User and group mapping.

.PARAMETER map_full
	 If true, user mappings queries the OneFS user database.  If false, only local authentication is queried.

.PARAMETER map_lookup_uid
	 If true, incoming UIDs are mapped to users in the OneFS user database.  If false, incoming UIDs are applied directly to file operations.

.PARAMETER map_retry
	 Determines whether lookups for users specified in map_all or map_root are retried if the look fails.

.PARAMETER map_root
	User and group mapping.

.PARAMETER max_file_size
	 The maximum file size in the export.

.PARAMETER readdirplus
	 If true, readdirplus requests are enabled.

.PARAMETER readdirplus_prefetch
	 Sets the number of directory entries that will be prefetched when a readdirplus request is processed.

.PARAMETER read_only
	 If true, the export is read-only.

.PARAMETER read_transfer_max_size
	 The maximum buffer size that clients should use on NFS read requests.  This option is advisory.

.PARAMETER read_transfer_multiple
	 The preferred multiple size for NFS read requests.  This option is advisory.

.PARAMETER read_transfer_size
	 The optimal size for NFS read requests.  This option is advisory.

.PARAMETER return_32bit_file_ids
	 Limits the size of file identifiers returned by NFSv3+ to 32-bit values.

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
	The synchronization type.

.PARAMETER write_datasync_reply
	The synchronization type.

.PARAMETER write_filesync_action
	The synchronization type.

.PARAMETER write_filesync_reply
	The synchronization type.

.PARAMETER write_transfer_max_size
	 The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	 The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	 The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The synchronization type.

.PARAMETER write_unstable_reply
	The synchronization type.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=33)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsExport')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/nfs/settings/export" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsExport

function Set-isiNfsSettingsGlobal{
<#
.SYNOPSIS
	Set Nfs Settings Global

.DESCRIPTION
	Modify the default values for NFS exports. All input fields are optional, but one or more must be supplied.

.PARAMETER lock_protection
	

.PARAMETER nfsv2_enabled
	Enable or disable NFSv2.

.PARAMETER nfsv3_enabled
	Enable or disable NFSv3.

.PARAMETER nfsv4_domain
	The domain or realm used to associate users and groups.

.PARAMETER nfsv4_enabled
	Enable or disable NFSv4.

.PARAMETER rpc_maxthreads
	Maximum number of threads in the nfsd thread pool.

.PARAMETER rpc_minthreads
	Minimum number of threads in the nfsd thread pool.

.PARAMETER service
	Enable or disable the nfs service.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$lock_protection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$nfsv2_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$nfsv3_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$nfsv4_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$nfsv4_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$rpc_maxthreads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$rpc_minthreads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsGlobal')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/nfs/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsGlobal

function Set-isiSmbSettingsGlobal{
<#
.SYNOPSIS
	Set Smb Settings Global

.DESCRIPTION
	Modify one or more settings.

.PARAMETER access_based_share_enum
	 Only enumerate files and folders the requesting user has access to.

.PARAMETER audit_fileshare
	 Specify level of file share audit events to log.

.PARAMETER audit_global_sacl
	 List of permissions to audit.

.PARAMETER audit_logon
	 Specify the level of logon audit events to log.

.PARAMETER dot_snap_accessible_child
	 Allow access to .snapshot directories in share subdirectories.

.PARAMETER dot_snap_accessible_root
	 Allow access to the .snapshot directory in the root of the share.

.PARAMETER dot_snap_visible_child
	 Show .snapshot directories in share subdirectories.

.PARAMETER dot_snap_visible_root
	 Show the .snapshot directory in the root of a share.

.PARAMETER enable_security_signatures
	 Indicates whether the server supports signed SMB packets.

.PARAMETER guest_user
	 Specifies the fully-qualified user to use for guest access.

.PARAMETER ignore_eas
	 Specify whether to ignore EAs on files.

.PARAMETER onefs_cpu_multiplier
	 Specify the number of OneFS driver worker threads per CPU.

.PARAMETER onefs_num_workers
	 Set the maximum number of OneFS driver worker threads.

.PARAMETER require_security_signatures
	 Indicates whether the server requires signed SMB packets.

.PARAMETER server_string
	 Provides a description of the server.

.PARAMETER service
	Specify whether service is enabled.

.PARAMETER srv_cpu_multiplier
	 Specify the number of SRV service worker threads per CPU.

.PARAMETER srv_num_workers
	 Set the maximum number of SRV service worker threads.

.PARAMETER support_multichannel
	 Support multichannel.

.PARAMETER support_netbios
	 Support NetBIOS.

.PARAMETER support_smb2
	 Support the SMB2 protocol on the server.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$access_based_share_enum,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$audit_fileshare,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$audit_global_sacl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$audit_logon,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$dot_snap_accessible_child,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$dot_snap_accessible_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$dot_snap_visible_child,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$dot_snap_visible_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$enable_security_signatures,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$guest_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$ignore_eas,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$onefs_cpu_multiplier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$onefs_num_workers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$require_security_signatures,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$server_string,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$srv_cpu_multiplier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$srv_num_workers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$support_multichannel,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$support_netbios,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$support_smb2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=21)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSettingsGlobal')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/smb/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSettingsGlobal

function Set-isiSmbSettingsShare{
<#
.SYNOPSIS
	Set Smb Settings Share

.DESCRIPTION
	Modify one or more settings.

.PARAMETER zone
	Zone which contains these share settings.

.PARAMETER access_based_enumeration
	 Only enumerate files and folders the requesting user has access to.

.PARAMETER access_based_enumeration_root_only
	 Access-based enumeration on only the root directory of the share.

.PARAMETER allow_delete_readonly
	 Allow deletion of read-only files in the share.

.PARAMETER allow_execute_always
	 Allows users to execute files they have read rights for.

.PARAMETER change_notify
	 Specify level of change notification alerts on the share.

.PARAMETER create_permissions
	 Set the create permissions for new files and directories in share.

.PARAMETER csc_policy
	 Client-side caching policy for the shares.

.PARAMETER directory_create_mask
	 Unix umask or mode bits.

.PARAMETER directory_create_mode
	 Unix umask or mode bits.

.PARAMETER file_create_mask
	 Unix umask or mode bits.

.PARAMETER file_create_mode
	 Unix umask or mode bits.

.PARAMETER hide_dot_files
	 Hide files and directories that begin with a period '.'.

.PARAMETER host_acl
	 An ACL expressing which hosts are allowed access. A deny clause must be the final entry.

.PARAMETER impersonate_guest
	 Specify the condition in which user access is done as the guest account.

.PARAMETER impersonate_user
	 User account to be used as guest account.

.PARAMETER mangle_byte_start
	 Specifies the wchar_t starting point for automatic byte mangling.

.PARAMETER mangle_map
	 Character mangle map.

.PARAMETER ntfs_acl_support
	 Support NTFS ACLs on files and directories.

.PARAMETER oplocks
	 Allow oplock requests.

.PARAMETER strict_flush
	 Handle SMB flush operations.

.PARAMETER strict_locking
	 Specifies whether byte range locks contend against SMB I/O.

.PARAMETER new_zone
	 Name of the access zone in which to update settings

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$mangle_map,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$oplocks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$new_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=23)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($new_zone){
				$BoundParameters.Remove('new_zone') | out-null
				$BoundParameters.Add('zone',$new_zone)
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSettingsShare')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/protocols/smb/settings/share" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSettingsShare

function Set-isiSmbShare{
<#
.SYNOPSIS
	Set Smb Share

.DESCRIPTION
	Modify share. All input fields are optional, but one or must be supplied.

.PARAMETER id
	Share id

.PARAMETER name
	Share name

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

.PARAMETER create_permissions
	 Create permissions for new files and directories in share.

.PARAMETER csc_policy
	 Client-side caching policy for the shares.

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

.PARAMETER impersonate_user
	 User account to be used as guest account.

.PARAMETER inheritable_path_acl
	 Set the inheritable ACL on the share path.

.PARAMETER mangle_byte_start
	 Specifies the wchar_t starting point for automatic byte mangling.

.PARAMETER mangle_map
	 Character mangle map.

.PARAMETER new_name
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

.PARAMETER new_zone
	 Name of the access zone to which to move this SMB share

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$allow_variable_expansion,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$auto_create_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$browsable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$inheritable_path_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$mangle_map,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$oplocks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$run_as_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$new_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=33)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($new_zone){
				$BoundParameters.Remove('new_zone') | out-null
				$BoundParameters.Add('zone',$new_zone)
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbShare')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/protocols/smb/shares/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbShare

function Set-isiQuota{
<#
.SYNOPSIS
	Set Quota

.DESCRIPTION
	Modify quota. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Quota id

.PARAMETER name
	Quota name

.PARAMETER container
	If true, SMB shares using the quota directory see the quota thresholds as share size.

.PARAMETER enforced
	True if the quota provides enforcement, otherwise a accounting quota.

.PARAMETER linked
	If false and the quota is linked, attempt to unlink.

.PARAMETER thresholds
	

.PARAMETER thresholds_include_overhead
	If true, thresholds apply to data plus filesystem overhead required to store the data (i.e. 'physical' usage).

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$container,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enforced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$linked,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$thresholds,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$thresholds_include_overhead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuota')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/quotas/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiQuota

function Set-isiQuotaNotifications{
<#
.SYNOPSIS
	Set Quota Notifications

.DESCRIPTION
	This method creates an empty set of rules so that the global rules are not used. The input must be an empty JSON object.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($quota_id){
				$parameter1 = $quota_id
				$BoundParameters.Remove('quota_id') | out-null
			} else {
				$parameter1 = $quota_name
				$BoundParameters.Remove('quota_name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaNotifications')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/quotas/$parameter1/notifications" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiQuotaNotifications

function Set-isiQuotaNotification{
<#
.SYNOPSIS
	Set Quota Notification

.DESCRIPTION
	Modify notification rule. All input fields are optional, but one or must be supplied.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER action_alert
	Send alert when rule matches.

.PARAMETER action_email_address
	Email a specific email address when rule matches.

.PARAMETER action_email_owner
	Email quota domain owner when rule matches.

.PARAMETER email_template
	Path of optional /ifs template file used for email actions.

.PARAMETER holdoff
	Time to wait between detections for rules triggered by user actions.

.PARAMETER schedule
	Schedule for rules that repeatedly notify.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$action_email_owner,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][object]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($quota_id){
				$parameter1 = $quota_id
				$BoundParameters.Remove('quota_id') | out-null
			} else {
				$parameter1 = $quota_name
				$BoundParameters.Remove('quota_name') | out-null
			}
			if ($id){
				$parameter2 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter2 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaNotification')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/quotas/$parameter1/notifications/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiQuotaNotification

function Set-isiQuotaSettingsMapping{
<#
.SYNOPSIS
	Set Quota Settings Mapping

.DESCRIPTION
	Modify the mapping.

.PARAMETER id
	Quota id

.PARAMETER name
	Quota name

.PARAMETER mapping
	The FQDN of destination domain to map to.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$mapping,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaSettingsMapping')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/settings/mappings/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiQuotaSettingsMapping

function Set-isiQuotaSettingsNotification{
<#
.SYNOPSIS
	Set Quota Settings Notification

.DESCRIPTION
	Modify notification rule. All input fields are optional, but one or must be supplied.

.PARAMETER id
	Notification id

.PARAMETER name
	Notification name

.PARAMETER action_alert
	Send alert when rule matches.

.PARAMETER action_email_address
	Email a specific email address when rule matches.

.PARAMETER action_email_owner
	Email quota domain owner when rule matches.

.PARAMETER email_template
	Path of optional /ifs template file used for email actions.

.PARAMETER holdoff
	Time to wait between detections for rules triggered by user actions.

.PARAMETER schedule
	Schedule for rules that repeatedly notify.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$action_email_owner,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][object]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaSettingsNotification')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/settings/notifications/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiQuotaSettingsNotification

function Set-isiQuotaSettingsReports{
<#
.SYNOPSIS
	Set Quota Settings Reports

.DESCRIPTION
	Modify one or more settings.

.PARAMETER live_dir
	The directory on /ifs where manual or live reports will be placed.

.PARAMETER live_retain
	 The number of manual reports to keep.

.PARAMETER schedule
	The isidate schedule used to generate reports.

.PARAMETER scheduled_dir
	The directory on /ifs where schedule reports will be placed.

.PARAMETER scheduled_retain
	 The number of scheduled reports to keep.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$live_dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$live_retain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$scheduled_dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$scheduled_retain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaSettingsReports')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/settings/reports" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiQuotaSettingsReports

function Set-isiRemoteSupport{
<#
.SYNOPSIS
	Set Remote Support

.DESCRIPTION
	Modify one or more settings.

.PARAMETER email_customer_on_failure
	 Email the customer if all trasmission methods fail.

.PARAMETER enabled
	 Enable ConnectEMC.

.PARAMETER primary_esrs_gateway
	 Primary ESRS Gateway. Necessary to enable ConnectEMC.

.PARAMETER remote_support_subnet
	 Network subnet to use for remote support.  Necessary to enable ConnectEMC.

.PARAMETER secondary_esrs_gateway
	 Secondary ESRS Gateway. Used if Primary is unavailable.

.PARAMETER use_smtp_failover
	 Use SMPT if primary and secondary gateways are unavailable.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$email_customer_on_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$primary_esrs_gateway,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$remote_support_subnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$secondary_esrs_gateway,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$use_smtp_failover,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiRemoteSupport')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/remotesupport/connectemc" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiRemoteSupport

function Set-isiSnapshotAlias{
<#
.SYNOPSIS
	Set Snapshot Aliase

.DESCRIPTION
	Modify snapshot alias. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

.PARAMETER new_name
	The user or system supplied snapshot alias name.

.PARAMETER target
	Target snapshot for this snapshot alias.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$target,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshotAlias')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/aliases/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnapshotAlias

function Set-isiSnapshotSchedule{
<#
.SYNOPSIS
	Set Snapshot Schedule

.DESCRIPTION
	Modify the schedule. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

.PARAMETER alias
	Alias name to create for each snapshot.

.PARAMETER duration
	Time in seconds added to creation time to construction expiration time.

.PARAMETER new_name
	The schedule name.

.PARAMETER path
	The /ifs path snapshotted.

.PARAMETER pattern
	Pattern expanded with strftime to create snapshot names.

.PARAMETER schedule
	The isidate compatible natural language description of the schedule.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$duration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshotSchedule')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/schedules/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnapshotSchedule

function Set-isiSnapshotSettings{
<#
.SYNOPSIS
	Set Snapshot Settings

.DESCRIPTION
	Modify one or more settings.

.PARAMETER autocreate
	True if the scheduled snapshot creation services is on.

.PARAMETER autodelete
	True if the scheduled snapshot deletion services is on.

.PARAMETER global_visible_accessible
	Global switch for other accessible and visible settings.

.PARAMETER local_root_accessible
	True if root .snapshot directory is accessible locally.

.PARAMETER local_root_visible
	True if root .snapshot directory is visible locally.

.PARAMETER local_subdir_accessible
	True if sub-directory .snapshot directory is accessible locally.

.PARAMETER nfs_root_accessible
	True if root .snapshot directory is accessible over NFS.

.PARAMETER nfs_root_visible
	True if root .snapshot directory is visible over NFS.

.PARAMETER nfs_subdir_accessible
	True if sub-directory .snapshot directory is accessible over NFS.

.PARAMETER reserve
	Percentage of space to reserve for snapshots.

.PARAMETER service
	True if the system allows snapshot creation.

.PARAMETER smb_root_accessible
	True if root .snapshot directory is accessible over SMB.

.PARAMETER smb_root_visible
	True if root .snapshot directory is visible over SMB.

.PARAMETER smb_subdir_accessible
	True if sub-directory .snapshot directory is accessible over SMB.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$autocreate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$autodelete,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$global_visible_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$local_root_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$local_root_visible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$local_subdir_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$nfs_root_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$nfs_root_visible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$nfs_subdir_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][object]$reserve,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$smb_root_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$smb_root_visible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$smb_subdir_accessible,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=14)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshotSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnapshotSettings

function Set-isiSnapshot{
<#
.SYNOPSIS
	Set Snapshot

.DESCRIPTION
	Modify snapshot. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

.PARAMETER alias
	Alias name to create for this snapshot. If null, remove any alias.

.PARAMETER expires
	The Unix Epoch time the snapshot will expire and be eligible for automatic deletion.

.PARAMETER new_name
	The user or system supplied snapshot name. This will be null for snapshots pending delete.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshot')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/snapshots/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnapshot

function Set-isiSnapshotLock{
<#
.SYNOPSIS
	Set Snapshot Lock

.DESCRIPTION
	Modify lock. All input fields are optional, but one or more must be supplied.

.PARAMETER snapshot_id
	Snapshot snapshot_id

.PARAMETER snapshot_name
	Snapshot snapshot_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER expires
	The Unix Epoch time the snapshot lock will expire and be eligible for automatic deletion.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($snapshot_id){
				$parameter1 = $snapshot_id
				$BoundParameters.Remove('snapshot_id') | out-null
			} else {
				$parameter1 = $snapshot_name
				$BoundParameters.Remove('snapshot_name') | out-null
			}
			if ($id){
				$parameter2 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter2 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshotLock')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/snapshots/$parameter1/locks/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnapshotLock

function Set-isiStoragepoolNodepool{
<#
.SYNOPSIS
	Set Storagepool Nodepool

.DESCRIPTION
	Modify node pool. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Nodepool id

.PARAMETER name
	Nodepool name

.PARAMETER l3
	Use SSDs in this node pool for L3 cache.

.PARAMETER lnns
	The nodes that are part of this node pool.

.PARAMETER new_name
	The node pool name.

.PARAMETER protection_policy
	The node pool protection policy.

.PARAMETER tier
	The name or ID of the node pool's tier, if it is in a tier.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$l3,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$lnns,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$protection_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$tier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiStoragepoolNodepool')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/storagepool/nodepools/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolNodepool

function Set-isiStoragepoolSettings{
<#
.SYNOPSIS
	Set Storagepool Settings

.DESCRIPTION
	Modify one or more settings.

.PARAMETER automatically_manage_io_optimization
	Automatically manage IO optimization settings on files.

.PARAMETER automatically_manage_protection
	Automatically manage protection settings on files.

.PARAMETER global_namespace_acceleration_enabled
	Optimize namespace operations by storing metadata on SSDs.

.PARAMETER protect_directories_one_level_higher
	Automatically add additional protection level to all directories.

.PARAMETER spillover_enabled
	Spill writes into other pools as needed.

.PARAMETER spillover_target
	Target pool for spilled writes.

.PARAMETER ssd_l3_cache_default_enabled
	The L3 Cache default enabled state. This specifies whether L3 Cache should be enabled on new node pools

.PARAMETER virtual_hot_spare_deny_writes
	Deny writes into reserved virtual hot spare space.

.PARAMETER virtual_hot_spare_hide_spare
	Hide reserved virtual hot spare space from free space counts.

.PARAMETER virtual_hot_spare_limit_drives
	The number of drives to reserve for the virtual hot spare, from 0-4.

.PARAMETER virtual_hot_spare_limit_percent
	The percent space to reserve for the virtual hot spare, from 0-20.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$automatically_manage_io_optimization,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$automatically_manage_protection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$global_namespace_acceleration_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$protect_directories_one_level_higher,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$spillover_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$spillover_target,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$ssd_l3_cache_default_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$virtual_hot_spare_deny_writes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$virtual_hot_spare_hide_spare,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$virtual_hot_spare_limit_drives,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$virtual_hot_spare_limit_percent,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=11)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiStoragepoolSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/storagepool/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolSettings

function Set-isiStoragepoolTier{
<#
.SYNOPSIS
	Set Storagepool Tier

.DESCRIPTION
	Modify tier. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Tier id

.PARAMETER name
	Tier name

.PARAMETER children
	The names or IDs of the tier's children.

.PARAMETER new_name
	The tier name.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$children,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiStoragepoolTier')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/storagepool/tiers/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolTier

function Set-isiSyncJob{
<#
.SYNOPSIS
	Set Sync Job

.DESCRIPTION
	Perform an action (pause, cancel, etc...) on a single job.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

.PARAMETER state
	The state of the job.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncJob')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/jobs/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncJob

function Set-isiSyncPolicy{
<#
.SYNOPSIS
	Set Sync Policy

.DESCRIPTION
	Modify a single SyncIQ policy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER action
	If 'copy', source files will be copied to the target cluster.  If 'sync', the target directory will be made an image of the source directory:  Files and directories that have been deleted on the source, have been moved within the target directory, or no longer match the selection criteria will be deleted from the target directory.

.PARAMETER burst_mode
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable UDP-based data transfer.

.PARAMETER changelist
	If true, retain previous source snapshot and incremental repstate, both of which are required for changelist creation.

.PARAMETER check_integrity
	If true, the sync target performs cyclic redundancy checks (CRC) on the data as it is received.

.PARAMETER conflicted
	NOTE: This field should not be changed without the help of Isilon support.  If true, the most recent run of this policy encountered an error and this policy will not start any more scheduled jobs until this field is manually set back to 'false'.

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

.PARAMETER log_removed_files
	If true, the system will log any files or directories that are deleted due to a sync.

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$burst_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$changelist,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$check_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$conflicted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$disable_file_split,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$disable_fofb,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$disable_stf,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$expected_dataloss,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$force_interface,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$log_removed_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$report_max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$report_max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$restrict_target_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$skip_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$source_exclude_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][array]$source_include_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][object]$source_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$source_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$source_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$source_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][string]$source_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$target_compare_initial_sync,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$target_detect_modifications,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$target_host,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$target_snapshot_alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$target_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$target_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$target_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=39)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncPolicy')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncPolicy

function Set-isiSyncRule{
<#
.SYNOPSIS
	Set Sync Rule

.DESCRIPTION
	Modify a single SyncIQ performance rule.

.PARAMETER id
	Rule id

.PARAMETER name
	Rule name

.PARAMETER description
	User-entered description of this performance rule.

.PARAMETER enabled
	Whether this performance rule is currently in effect during its specified intervals.

.PARAMETER limit
	Amount the specified system resource type is limited by this rule.  Units are kb/s for bandwidth, files/s for file-count, or processing percentage used for cpu.

.PARAMETER schedule
	A schedule defining when during a week this performance rule is in effect.  If unspecified or null, the schedule will always be in effect.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncRule')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/rules/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncRule

function Set-isiSyncSettings{
<#
.SYNOPSIS
	Set Sync Settings

.DESCRIPTION
	Modify the global SyncIQ settings.  All input fields are optional, but one or more must be supplied.

.PARAMETER burst_memory_constraint
	The per-worker burst socket memory constraint, in bytes.

.PARAMETER burst_socket_buffer_size
	The per-worker burst socket buffer coalesced data, in bytes.

.PARAMETER force_interface
	NOTE: This field should not be changed without the help of Isilon support.  Default for the "force_interface" property that will be applied to each new sync policy unless otherwise specified at the time of policy creation.  Determines whether data is sent only through the subnet and pool specified in the "source_network" field. This option can be useful if there are multiple interfaces for the given source subnet.

.PARAMETER report_email
	Email sync reports to these addresses.

.PARAMETER report_max_age
	The default length of time (in seconds) a policy report will be stored.

.PARAMETER report_max_count
	The default maximum number of reports to retain for a policy.

.PARAMETER restrict_target_network
	Default for the "restrict_target_network" property that will be applied to each new sync policy unless otherwise specified at the time of policy creation.  If you specify true, and you specify a SmartConnect zone in the "target_host" field, replication policies will connect only to nodes in the specified SmartConnect zone.  If you specify false, replication policies are not restricted to specific nodes on the target cluster.

.PARAMETER service
	Specifies if the SyncIQ service currently on, paused, or off.  If paused, all sync jobs will be paused.  If turned off, all jobs will be canceled.

.PARAMETER source_network
	Restricts replication policies on the local cluster to running on the specified subnet and pool.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$burst_memory_constraint,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$burst_socket_buffer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$force_interface,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$report_email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$report_max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$report_max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$restrict_target_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$source_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncSettings

function Set-isiWormDomain{
<#
.SYNOPSIS
	Set Worm Domain

.DESCRIPTION
	Modify a single WORM domain.

.PARAMETER id
	Domain id

.PARAMETER name
	Domain name

.PARAMETER autocommit_offset
	The autocommit time period in seconds for the domain.  After a file exists in this domain without being modified for the specified time period, the file is automatically committed the next time the file is accessed.  If null, there is no autocommit time so files must be manually committed.

.PARAMETER default_retention
	

.PARAMETER max_retention
	

.PARAMETER min_retention
	

.PARAMETER override_date
	Override retention date for the domain.  If this date is later than any committed file's own retention date, that file will remain protected beyond its own retention date until this date.

.PARAMETER privileged_delete
	If 'on', files in this domain can be deleted using the privileged delete feature.  Otherwise, they can't be deleted even with privileged delete.  If 'disabled', privileged file deletes are permanently disabled and cannot be turned back on again.

.PARAMETER type
	Whether this is an enterprise domain or this is a compliance domain. Compliance domains may not be created on enterprise clusters. Enterprise and compliance domains may be created on compliance clusters.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$autocommit_offset,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$default_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][object]$max_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$min_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][object]$override_date,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$privileged_delete,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiWormDomain')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/worm/domains/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiWormDomain

function Set-isiWormSettings{
<#
.SYNOPSIS
	Set Worm Settings

.DESCRIPTION
	Modify the global WORM settings.  All input fields are optional, but one or more must be supplied.

.PARAMETER cdate
	To set the compliance clock to the current system time, PUT to this resource with an empty JSON object {} for the cdate value.  This cluster must be in compliance mode to set the compliance clock.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$cdate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiWormSettings')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/worm/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiWormSettings

function Set-isiZone{
<#
.SYNOPSIS
	Set Zone

.DESCRIPTION
	Modify the access zone. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Zone id

.PARAMETER name
	Zone name

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

.PARAMETER hdfs_root_directory
	 Root directory for HDFS protocol.

.PARAMETER home_directory_umask
	 Permissions set on auto-created user home directories.

.PARAMETER ifs_restricted
	 User restrictions for this zone.

.PARAMETER map_untrusted
	 Maps untrusted domains to this NetBIOS domain during authentication.

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$all_auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$alternate_system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$audit_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$audit_success,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][array]$auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$cache_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$hdfs_ambari_namenode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$hdfs_ambari_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$hdfs_authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$hdfs_root_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$home_directory_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$ifs_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$map_untrusted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$netbios_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$protocol_audit_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$skeleton_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][array]$syslog_audit_events,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$syslog_forwarding_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$user_mapping_rules,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$webhdfs_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=25)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiZone')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/zones/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiZone

function Set-isiNfsAliasV2{
<#
.SYNOPSIS
	Set Nfs Aliase

.DESCRIPTION
	Modify the alias. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Aid id

.PARAMETER name
	Aid name

.PARAMETER zone
	Access zone

.PARAMETER health
	The health of the alias.

.PARAMETER new_name
	The name by which the alias can be referenced

.PARAMETER path
	The path to which the alias points

.PARAMETER new_zone
	The zone in which the alias is valid

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$health,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$new_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($id){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($new_zone){
				$BoundParameters.Remove('new_zone') | out-null
				$BoundParameters.Add('zone',$new_zone)
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsAliasV2')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/2/protocols/nfs/aliases/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsAliasV2

function Set-isiNfsExportV2{
<#
.SYNOPSIS
	Set Nfs Export

.DESCRIPTION
	Modify the export. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	 id

.PARAMETER enforce
	If true, the export will be updated even if that change conflicts with another export.

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
	User and group mapping.

.PARAMETER map_failure
	User and group mapping.

.PARAMETER map_full
	 If true, user mappings queries the OneFS user database.  If false, only local authentication is queried.

.PARAMETER map_lookup_uid
	 If true, incoming UIDs are mapped to users in the OneFS user database.  If false, incoming UIDs are applied directly to file operations.

.PARAMETER map_non_root
	User and group mapping.

.PARAMETER map_retry
	 Determines whether lookups for users specified in map_all, map_root or map_nonroot are retried if the look fails.

.PARAMETER map_root
	User and group mapping.

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
	The synchronization type.

.PARAMETER write_datasync_reply
	The synchronization type.

.PARAMETER write_filesync_action
	The synchronization type.

.PARAMETER write_filesync_reply
	The synchronization type.

.PARAMETER write_transfer_max_size
	 The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	 The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	 The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The synchronization type.

.PARAMETER write_unstable_reply
	The synchronization type.

.PARAMETER new_zone
	 The zone in which the export is valid

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$case_insensitive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$case_preserving,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$chown_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$link_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][object]$map_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][object]$map_non_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$name_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$no_truncate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=49)][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=50)][string]$new_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=51)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=52)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$parameter1 = $id
			$BoundParameters.Remove('id') | out-null
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
				$BoundParameters = $BoundParameters.Remove('$enforce')
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($new_zone){
				$BoundParameters.Remove('new_zone') | out-null
				$BoundParameters.Add('zone',$new_zone)
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsExportV2')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/2/protocols/nfs/exports/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsExportV2

function Set-isiNfsSettingsExportV2{
<#
.SYNOPSIS
	Set Nfs Settings Export

.DESCRIPTION
	Modify the default values for NFS exports. All input fields are optional, but one or more must be supplied.

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

.PARAMETER commit_asynchronous
	 If true, allows NFS  commit  requests to  execute asynchronously.

.PARAMETER directory_transfer_size
	 The preferred size for directory read operations.  This option is advisory.

.PARAMETER encoding
	 The character encoding of clients connecting to the export.

.PARAMETER link_max
	 The reported maximum number of links to a file.

.PARAMETER map_all
	User and group mapping.

.PARAMETER map_failure
	User and group mapping.

.PARAMETER map_full
	 If true, user mappings queries the OneFS user database.  If false, only local authentication is queried.

.PARAMETER map_lookup_uid
	 If true, incoming UIDs are mapped to users in the OneFS user database.  If false, incoming UIDs are applied directly to file operations.

.PARAMETER map_non_root
	User and group mapping.

.PARAMETER map_retry
	 Determines whether lookups for users specified in map_all, map_root or map_nonroot are retried if the look fails.

.PARAMETER map_root
	User and group mapping.

.PARAMETER max_file_size
	 The maximum file size in the export.

.PARAMETER name_max_size
	 The reported maximum length of a file name.

.PARAMETER no_truncate
	 If true, report that too-long file names result in an error

.PARAMETER readdirplus
	 If true, readdirplus requests are enabled.

.PARAMETER readdirplus_prefetch
	 This field is deprecated and does not do anything.

.PARAMETER read_only
	 If true, the export is read-only.

.PARAMETER read_transfer_max_size
	 The maximum buffer size that clients should use on NFS read requests.  This option is advisory.

.PARAMETER read_transfer_multiple
	 The preferred multiple size for NFS read requests.  This option is advisory.

.PARAMETER read_transfer_size
	 The optimal size for NFS read requests.  This option is advisory.

.PARAMETER return_32bit_file_ids
	 Limits the size of file identifiers returned by NFSv3+ to 32-bit values.

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
	The synchronization type.

.PARAMETER write_datasync_reply
	The synchronization type.

.PARAMETER write_filesync_action
	The synchronization type.

.PARAMETER write_filesync_reply
	The synchronization type.

.PARAMETER write_transfer_max_size
	 The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	 The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	 The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The synchronization type.

.PARAMETER write_unstable_reply
	The synchronization type.

.PARAMETER new_zone
	 The zone in which the export is valid

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$case_insensitive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$case_preserving,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$chown_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$link_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$map_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][object]$map_non_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$name_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$no_truncate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][string]$new_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=43)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
				$BoundParameters = $BoundParameters.Remove('$zone')
			}
			if ($new_zone){
				$BoundParameters.Remove('new_zone') | out-null
				$BoundParameters.Add('zone',$new_zone)
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsExportV2')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/2/protocols/nfs/settings/export" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters)  -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsExportV2

function Set-isiNfsSettingsGlobalV2{
<#
.SYNOPSIS
	Set Nfs Settings Global

.DESCRIPTION
	Modify the default values for NFS exports. All input fields are optional, but one or more must be supplied.

.PARAMETER lock_protection
	

.PARAMETER nfsv3_enabled
	Enable or disable NFSv3.

.PARAMETER nfsv4_enabled
	Enable or disable NFSv4.

.PARAMETER rpc_maxthreads
	Maximum number of threads in the nfs server thread pool.

.PARAMETER rpc_minthreads
	Minimum number of threads in the nfs server thread pool.

.PARAMETER service
	Enable or disable the nfs service.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$lock_protection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$nfsv3_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$nfsv4_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$rpc_maxthreads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$rpc_minthreads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsGlobalV2')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/2/protocols/nfs/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsGlobalV2

function Set-isiNfsSettingsZoneV2{
<#
.SYNOPSIS
	Set Nfs Settings Zone

.DESCRIPTION
	Modify the NFS server settings for this zone.

.PARAMETER nfsv4_allow_numeric_ids
	 Send owners/groups as UIDs/GIDs when lookups fail or if no_names=1 (v4)

.PARAMETER nfsv4_domain
	 The domain or realm used to associate users and groups.

.PARAMETER nfsv4_no_domain
	 Send owners/groups without domainname (v4)

.PARAMETER nfsv4_no_domain_uids
	 Send UIDs/GIDs without domainname (v4)

.PARAMETER nfsv4_no_names
	 Always send owners/groups as UIDs/GIDs (v4)

.PARAMETER nfsv4_replace_domain
	 Replace owner/group domain with nfs domainname. (v4)

.PARAMETER zone
	 The zone in which these settings apply

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$nfsv4_allow_numeric_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$nfsv4_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$nfsv4_no_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$nfsv4_no_domain_uids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$nfsv4_no_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$nfsv4_replace_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsZoneV2')){
			$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/2/protocols/nfs/settings/zone" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			$ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsZoneV2


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


function Get-isiAuditSettings{
<#
.SYNOPSIS
	Get Audit Settings

.DESCRIPTION
	Retrieves the auditing global settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/audit/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuditSettings

function Get-isiAuditTopics{
<#
.SYNOPSIS
	Get Audit Topics

.DESCRIPTION
	Retrieve a list of audit topics.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/audit/topics" -Cluster $Cluster
			return $ISIObject.topics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuditTopics

function Get-isiAuditTopic{
<#
.SYNOPSIS
	Get Audit Topic

.DESCRIPTION
	Retrieve the audit topic information.

.PARAMETER id
	Topic id

.PARAMETER name
	Topic name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/audit/topics/$parameter1" -Cluster $Cluster
			return $ISIObject.topics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuditTopic

function Get-isiAuthAccess{
<#
.SYNOPSIS
	Get Auth Access

.DESCRIPTION
	Determine user's access rights to a file

.PARAMETER id
	User id

.PARAMETER name
	User name

.PARAMETER numeric
	Show the user's numeric identifier.

.PARAMETER path
	Path to the file. Must be within /ifs.

.PARAMETER zone
	Access zone the user is in.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$numeric,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($numeric){
				$queryArguments += 'numeric=' + $numeric
			}
			if ($path){
				$queryArguments += 'path=' + $path
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/access/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.access
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthAccess

function Get-isiAuthGroups{
<#
.SYNOPSIS
	Get Auth Groups

.DESCRIPTION
	List all groups.

.PARAMETER cached
	If true, only return cached objects.

.PARAMETER domain
	Filter groups by domain.

.PARAMETER filter
	Filter groups by name prefix.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER provider
	Filter groups by provider.

.PARAMETER query_member_of
	Enumerate all groups that a group is a member of.

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER zone
	Filter groups by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$query_member_of,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($cached){
				$queryArguments += 'cached=' + $cached
			}
			if ($domain){
				$queryArguments += 'domain=' + $domain
			}
			if ($filter){
				$queryArguments += 'filter=' + $filter
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($query_member_of){
				$queryArguments += 'query_member_of=' + $query_member_of
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/groups" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.groups,$ISIObject.resume
			}else{
				return $ISIObject.groups
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthGroups

function Get-isiAuthGroup{
<#
.SYNOPSIS
	Get Auth Group

.DESCRIPTION
	Retrieve the group information.

.PARAMETER id
	Group id

.PARAMETER name
	Group name

.PARAMETER cached
	If true, only return cached objects.

.PARAMETER provider
	Filter groups by provider.

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER zone
	Filter groups by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($cached){
				$queryArguments += 'cached=' + $cached
			}
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/groups/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.groups
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthGroup

function Get-isiAuthGroupMembers{
<#
.SYNOPSIS
	Get Auth Group Members

.DESCRIPTION
	List all the members of the group.

.PARAMETER group_id
	Group group_id

.PARAMETER group_name
	Group group_name

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER provider
	Filter group members by provider.

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER zone
	Filter group members by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$group_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$group_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('group_id')){
				$parameter1 = $group_id
			} else {
				$parameter1 = $group_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/groups/$parameter1/members" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.members
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthGroupMembers

function Get-isiAuthId{
<#
.SYNOPSIS
	Get Auth Id

.DESCRIPTION
	Retrieve the current security token.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/id" -Cluster $Cluster
			return $ISIObject.ntoken
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthId

function Get-isiAuthMappingIdentities{
<#
.SYNOPSIS
	Get Auth Mapping Identity

.DESCRIPTION
	Retrieve all identity mappings (uid, gid, sid, and on-disk) for the supplied source persona.

.PARAMETER id
	Source id

.PARAMETER name
	Source name

.PARAMETER nocreate
	Idmap should attempt to create missing identity mappings.

.PARAMETER zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$nocreate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($nocreate){
				$queryArguments += 'nocreate=' + $nocreate
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/mapping/identities/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.identities
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthMappingIdentities

function Get-isiAuthMappingUsersLookup{
<#
.SYNOPSIS
	Get Auth Mapping Users Lookup

.DESCRIPTION
	Retrieve the user information.

.PARAMETER gid
	The IDs of the groups that the user belongs to.

.PARAMETER primary_gid
	The user's primary group ID.

.PARAMETER uid
	The user ID.

.PARAMETER user
	The user name.

.PARAMETER zone
	The zone the user bolongs to.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][array]$gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$primary_gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($gid){
				$queryArguments += 'gid=' + $gid
			}
			if ($primary_gid){
				$queryArguments += 'primary_gid=' + $primary_gid
			}
			if ($uid){
				$queryArguments += 'uid=' + $uid
			}
			if ($user){
				$queryArguments += 'user=' + $user
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/mapping/users/lookup" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.mapping
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthMappingUsersLookup

function Get-isiAuthMappingUsersRules{
<#
.SYNOPSIS
	Get Auth Mapping Users Rules

.DESCRIPTION
	Retrieve the user mapping rules.

.PARAMETER zone
	The zone to which the user mapping applies.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/mapping/users/rules" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.rules
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthMappingUsersRules

function Get-isiAuthNetgroup{
<#
.SYNOPSIS
	Get Auth Netgroup

.DESCRIPTION
	Retrieve the user information.

.PARAMETER id
	Netgroup id

.PARAMETER name
	Netgroup name

.PARAMETER ignore_errors
	Ignore netgroup errors.

.PARAMETER provider
	Filter users by provider.

.PARAMETER recursive
	Perform recursive search.

.PARAMETER zone
	Filter users by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$ignore_errors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$recursive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($ignore_errors){
				$queryArguments += 'ignore_errors=' + $ignore_errors
			}
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($recursive){
				$queryArguments += 'recursive=' + $recursive
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/netgroups/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.netgroups
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthNetgroup

function Get-isiAuthPrivileges{
<#
.SYNOPSIS
	Get Auth Privileges

.DESCRIPTION
	List all privileges.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/privileges" -Cluster $Cluster
			return $ISIObject.privileges
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthPrivileges

function Get-isiAuthProvidersAds{
<#
.SYNOPSIS
	Get Auth Providers Ads

.DESCRIPTION
	List all ADS providers.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/ads" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ads
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersAds

function Get-isiAuthProviderAds{
<#
.SYNOPSIS
	Get Auth Provider Ads

.DESCRIPTION
	Retrieve the ADS provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/ads/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ads
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAds

function Get-isiAuthProviderAdsControllers{
<#
.SYNOPSIS
	Get Auth Provider Ads Controllers

.DESCRIPTION
	List all ADS controllers.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/providers/ads/$parameter1/controllers" -Cluster $Cluster
			return $ISIObject.controllers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsControllers

function Get-isiAuthProviderAdsDomains{
<#
.SYNOPSIS
	Get Auth Provider Ads Domains

.DESCRIPTION
	List all ADS domains.

.PARAMETER ads_id
	Provider ads_id

.PARAMETER ads_name
	Provider ads_name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$ads_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$ads_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('ads_id')){
				$parameter1 = $ads_id
			} else {
				$parameter1 = $ads_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/ads/$parameter1/domains" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.domains
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsDomains

function Get-isiAuthProviderAdsDomain{
<#
.SYNOPSIS
	Get Auth Provider Ads Domain

.DESCRIPTION
	Retrieve the ADS domain information.

.PARAMETER ads_id
	Provider ads_id

.PARAMETER ads_name
	Provider ads_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$ads_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$ads_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('ads_id')){
				$parameter1 = $ads_id
			} else {
				$parameter1 = $ads_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/providers/ads/$parameter1/domains/$parameter2" -Cluster $Cluster
			return $ISIObject.domains
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsDomain

function Get-isiAuthProviderAdsSearch{
<#
.SYNOPSIS
	Get Auth Provider Ads Search

.DESCRIPTION
	Retrieve search results.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER description
	The user or group description to search for.

.PARAMETER domain
	The domain to search in.

.PARAMETER filter
	The LDAP filter to apply to the search.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER password
	The password for the domain if untrusted.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER search_groups
	If true, search for groups.

.PARAMETER search_users
	If true, search for users.

.PARAMETER user
	The user name for the domain if untrusted.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][bool]$search_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][bool]$search_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($description){
				$queryArguments += 'description=' + $description
			}
			if ($domain){
				$queryArguments += 'domain=' + $domain
			}
			if ($filter){
				$queryArguments += 'filter=' + $filter
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($password){
				$queryArguments += 'password=' + $password
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($search_groups){
				$queryArguments += 'search_groups=' + $search_groups
			}
			if ($search_users){
				$queryArguments += 'search_users=' + $search_users
			}
			if ($user){
				$queryArguments += 'user=' + $user
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/ads/$parameter1/search" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.objects,$ISIObject.resume
			}else{
				return $ISIObject.objects
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsSearch

function Get-isiAuthProvidersFile{
<#
.SYNOPSIS
	Get Auth Providers File

.DESCRIPTION
	List all file providers.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/file" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.file
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersFile

function Get-isiAuthProviderFile{
<#
.SYNOPSIS
	Get Auth Provider File

.DESCRIPTION
	Retrieve the file provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/file/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.file
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderFile

function Get-isiAuthProvidersKrb5{
<#
.SYNOPSIS
	Get Auth Providers Krb5

.DESCRIPTION
	List all KRB5 providers.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/krb5" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.krb5
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersKrb5

function Get-isiAuthProviderKrb5{
<#
.SYNOPSIS
	Get Auth Provider Krb5

.DESCRIPTION
	Retrieve the KRB5 provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/krb5/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.krb5
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderKrb5

function Get-isiAuthProvidersLdap{
<#
.SYNOPSIS
	Get Auth Providers Ldap

.DESCRIPTION
	List all LDAP providers.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/ldap" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ldap
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersLdap

function Get-isiAuthProviderLdap{
<#
.SYNOPSIS
	Get Auth Provider Ldap

.DESCRIPTION
	Retrieve the LDAP provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/ldap/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ldap
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderLdap

function Get-isiAuthProvidersLocal{
<#
.SYNOPSIS
	Get Auth Providers Local

.DESCRIPTION
	List all local providers.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/local" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.local
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersLocal

function Get-isiAuthProviderLocal{
<#
.SYNOPSIS
	Get Auth Provider Local

.DESCRIPTION
	Retrieve the local provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/local/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.local
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderLocal

function Get-isiAuthProvidersNis{
<#
.SYNOPSIS
	Get Auth Providers Nis

.DESCRIPTION
	List all NIS providers.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/nis" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.nis
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersNis

function Get-isiAuthProviderNis{
<#
.SYNOPSIS
	Get Auth Provider Nis

.DESCRIPTION
	Retrieve the NIS provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/nis/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.nis
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderNis

function Get-isiAuthProvidersSummary{
<#
.SYNOPSIS
	Get Auth Providers Summary

.DESCRIPTION
	Retrieve the summary information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/providers/summary" -Cluster $Cluster
			return $ISIObject.provider_instances
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersSummary

function Get-isiAuthRoles{
<#
.SYNOPSIS
	Get Auth Roles

.DESCRIPTION
	List all roles.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER resolve_names
	Filter users by zone.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/roles" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.roles
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthRoles

function Get-isiAuthRole{
<#
.SYNOPSIS
	Get Auth Role

.DESCRIPTION
	Retrieve the role information.

.PARAMETER id
	Role id

.PARAMETER name
	Role name

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/roles/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.roles
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthRole

function Get-isiAuthRoleMembers{
<#
.SYNOPSIS
	Get Auth Role Members

.DESCRIPTION
	List all the members of the role.

.PARAMETER role_id
	Role role_id

.PARAMETER role_name
	Role role_name

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$role_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$role_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
			} else {
				$parameter1 = $role_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/roles/$parameter1/members" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.members
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthRoleMembers

function Get-isiAuthRolePrivileges{
<#
.SYNOPSIS
	Get Auth Role Privileges

.DESCRIPTION
	List all privileges in the role.

.PARAMETER role_id
	Role role_id

.PARAMETER role_name
	Role role_name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$role_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$role_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
			} else {
				$parameter1 = $role_name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/roles/$parameter1/privileges" -Cluster $Cluster
			return $ISIObject.privileges
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthRolePrivileges

function Get-isiAuthSettingsGlobal{
<#
.SYNOPSIS
	Get Auth Settings Global

.DESCRIPTION
	Retrieve the global settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER zone
	Zone which contains any per-zone settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/settings/global" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.global_settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsGlobal

function Get-isiAuthSettingsKrb5Defaults{
<#
.SYNOPSIS
	Get Auth Settings Krb5 Defaults

.DESCRIPTION
	Retrieve the krb5 settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/settings/krb5/defaults" -Cluster $Cluster
			return $ISIObject.krb5_settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsKrb5Defaults

function Get-isiAuthSettingsKrb5Domains{
<#
.SYNOPSIS
	Get Auth Settings Krb5 Domains

.DESCRIPTION
	Retrieve the krb5 settings for domains.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/settings/krb5/domains" -Cluster $Cluster
			return $ISIObject.domain
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsKrb5Domains

function Get-isiAuthSettingsKrb5Domain{
<#
.SYNOPSIS
	Get Auth Settings Krb5 Domain

.DESCRIPTION
	View the krb5 domain settings.

.PARAMETER id
	Domain id

.PARAMETER name
	Domain name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/settings/krb5/domains/$parameter1" -Cluster $Cluster
			return $ISIObject.domain
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsKrb5Domain

function Get-isiAuthSettingsKrb5Realms{
<#
.SYNOPSIS
	Get Auth Settings Krb5 Realms

.DESCRIPTION
	Retrieve the krb5 settings for realms.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/settings/krb5/realms" -Cluster $Cluster
			return $ISIObject.realm
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsKrb5Realms

function Get-isiAuthSettingsKrb5Realm{
<#
.SYNOPSIS
	Get Auth Settings Krb5 Realm

.DESCRIPTION
	Retrieve the krb5 settings for realms.

.PARAMETER id
	Realm id

.PARAMETER name
	Realm name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/settings/krb5/realms/$parameter1" -Cluster $Cluster
			return $ISIObject.realm
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsKrb5Realm

function Get-isiAuthSettingsMapping{
<#
.SYNOPSIS
	Get Auth Settings Mapping

.DESCRIPTION
	Retrieve the mapping settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER zone
	Access zone which contains mapping settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/settings/mapping" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.mapping_settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsMapping

function Get-isiAuthShells{
<#
.SYNOPSIS
	Get Auth Shells

.DESCRIPTION
	List all shells.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/shells" -Cluster $Cluster
			return $ISIObject.shells
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthShells

function Get-isiAuthUsers{
<#
.SYNOPSIS
	Get Auth Users

.DESCRIPTION
	List all users.

.PARAMETER cached
	If true, only return cached objects.

.PARAMETER domain
	Filter users by domain.

.PARAMETER filter
	Filter users by name prefix.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER provider
	Filter users by provider.

.PARAMETER query_member_of
	Enumerate all users that a group is a member of.

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER zone
	Filter users by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$query_member_of,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($cached){
				$queryArguments += 'cached=' + $cached
			}
			if ($domain){
				$queryArguments += 'domain=' + $domain
			}
			if ($filter){
				$queryArguments += 'filter=' + $filter
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($query_member_of){
				$queryArguments += 'query_member_of=' + $query_member_of
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/users" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.users,$ISIObject.resume
			}else{
				return $ISIObject.users
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthUsers

function Get-isiAuthUser{
<#
.SYNOPSIS
	Get Auth User

.DESCRIPTION
	Retrieve the user information.

.PARAMETER id
	User id

.PARAMETER name
	User name

.PARAMETER cached
	If true, only return cached objects.

.PARAMETER provider
	Filter users by provider.

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER zone
	Filter users by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($cached){
				$queryArguments += 'cached=' + $cached
			}
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/users/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.users
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthUser

function Get-isiAuthUserMemberOfGroups{
<#
.SYNOPSIS
	Get Auth User Member Of Groups

.DESCRIPTION
	List all groups the user is a member of.

.PARAMETER user_id
	User user_id

.PARAMETER user_name
	User user_name

.PARAMETER provider
	Filter groups by provider.

.PARAMETER resolve_names
	Resolve names of personas.

.PARAMETER zone
	Filter groups by zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$user_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$user_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
			} else {
				$parameter1 = $user_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/users/$parameter1/member_of" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.member_of
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthUserMemberOfGroups

function Get-isiAuthWellknowns{
<#
.SYNOPSIS
	Get Auth Wellknowns

.DESCRIPTION
	List all wellknown personas.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/auth/wellknowns" -Cluster $Cluster
			return $ISIObject.wellknowns
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthWellknowns

function Get-isiAuthWellknown{
<#
.SYNOPSIS
	Get Auth Wellknown

.DESCRIPTION
	Retrieve the wellknown persona.

.PARAMETER id
	Wellknown id

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			$parameter1 = $id
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/wellknowns/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.wellknowns
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthWellknown

function Get-isiCloudAccounts{
<#
.SYNOPSIS
	Get Cloud Accounts

.DESCRIPTION
	List all accounts.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/cloud/accounts" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.accounts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudAccounts

function Get-isiCloudAccount{
<#
.SYNOPSIS
	Get Cloud Account

.DESCRIPTION
	Retrieve cloud account information.

.PARAMETER id
	Account id

.PARAMETER name
	Account name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cloud/accounts/$parameter1" -Cluster $Cluster
			return $ISIObject.accounts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudAccount

function Get-isiCloudJobs{
<#
.SYNOPSIS
	Get Cloud Jobs

.DESCRIPTION
	List all cloudpools jobs.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/cloud/jobs" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudJobs

function Get-isiCloudJobsFile{
<#
.SYNOPSIS
	Get Cloud Jobs File

.DESCRIPTION
	Retrieve files associated with a cloudpool job.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

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
			$queryArguments = @()
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/cloud/jobs-files/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.files
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudJobsFile

function Get-isiCloudJob{
<#
.SYNOPSIS
	Get Cloud Job

.DESCRIPTION
	Retrieve cloudpool job information.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

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
			$queryArguments = @()
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/cloud/jobs/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudJob

function Get-isiCloudPools{
<#
.SYNOPSIS
	Get Cloud Pools

.DESCRIPTION
	List all pools.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/cloud/pools" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.pools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudPools

function Get-isiCloudPool{
<#
.SYNOPSIS
	Get Cloud Pool

.DESCRIPTION
	Retrieve cloud pool information

.PARAMETER id
	Pool id

.PARAMETER name
	Pool name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cloud/pools/$parameter1" -Cluster $Cluster
			return $ISIObject.pools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudPool

function Get-isiCloudSettings{
<#
.SYNOPSIS
	Get Cloud Settings

.DESCRIPTION
	List all cloud settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cloud/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudSettings

function Get-isiClusterConfig{
<#
.SYNOPSIS
	Get Cluster Config

.DESCRIPTION
	Retrieve the cluster information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/config" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterConfig

function Get-isiClusterExternalIPs{
<#
.SYNOPSIS
	Get Cluster External IPs

.DESCRIPTION
	Retrieve the cluster IP addresses.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/external-ips" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterExternalIPs

function Get-isiClusterIdentity{
<#
.SYNOPSIS
	Get Cluster Identity

.DESCRIPTION
	Retrieve the login information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/identity" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterIdentity

function Get-isiClusterFsStats{
<#
.SYNOPSIS
	Get Cluster FS Stats

.DESCRIPTION
	Retrieve the filesystem statistics.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/statfs" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterFsStats

function Get-isiClusterTime{
<#
.SYNOPSIS
	Get Cluster Time

.DESCRIPTION
	Retrieve the current cluster time.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/time" -Cluster $Cluster
			return $ISIObject.time
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterTime

function Get-isiDebugStats{
<#
.SYNOPSIS
	Get Debug Stats

.DESCRIPTION
	List cumulative call statistics for each resource.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/debug/stats" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiDebugStats

function Get-isiDedupeDedupeSummary{
<#
.SYNOPSIS
	Get Dedupe Summary

.DESCRIPTION
	Return summary information about dedupe.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/dedupe/dedupe-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiDedupeDedupeSummary

function Get-isiDedupeReports{
<#
.SYNOPSIS
	Get Dedupe Reports

.DESCRIPTION
	List dedupe reports.

.PARAMETER begin
	Restrict the query to reports at or after the given time, in seconds since the Epoch.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER end
	Restrict the query to reports at or before the given time, in seconds since the Epoch.

.PARAMETER job_id
	Restrict the query to the given job ID.

.PARAMETER job_type
	Restrict the query to the given job type.
	Valid inputs: Dedupe,DedupeAssessment

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.
	Valid inputs: id,start_time,end_time

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$job_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('Dedupe','DedupeAssessment')][string]$job_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][ValidateSet('id','start_time','end_time')][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($job_id){
				$queryArguments += 'job_id=' + $job_id
			}
			if ($job_type){
				$queryArguments += 'job_type=' + $job_type
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/dedupe/reports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiDedupeReports

function Get-isiDedupeReport{
<#
.SYNOPSIS
	Get Dedupe Report

.DESCRIPTION
	Retrieve a report for a single dedupe job.

.PARAMETER id
	Report id

.PARAMETER name
	Report name

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/dedupe/reports/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiDedupeReport

function Get-isiDedupeSettings{
<#
.SYNOPSIS
	Get Dedupe Settings

.DESCRIPTION
	Retrieve the dedupe settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/dedupe/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiDedupeSettings

function Get-isiFilepoolDefaultPolicy{
<#
.SYNOPSIS
	Get Filepool Default Policy

.DESCRIPTION
	List default file pool policy.

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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/filepool/default-policy" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.'default-policy'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilepoolDefaultPolicy

function Get-isiFilepoolPolicies{
<#
.SYNOPSIS
	Get Filepool Policies

.DESCRIPTION
	List all policies.

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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/filepool/policies" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.policies
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilepoolPolicies

function Get-isiFilepoolPolicy{
<#
.SYNOPSIS
	Get Filepool Policy

.DESCRIPTION
	Retrieve file pool policy information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/filepool/policies/$parameter1" -Cluster $Cluster
			return $ISIObject.policies
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilepoolPolicy

function Get-isiFilepoolTemplates{
<#
.SYNOPSIS
	Get Filepool Templates

.DESCRIPTION
	List all templates.

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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/filepool/templates" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.templates
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilepoolTemplates

function Get-isiFilepoolTemplate{
<#
.SYNOPSIS
	Get Filepool Template

.DESCRIPTION
	List all templates.

.PARAMETER id
	Template id

.PARAMETER name
	Template name

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
			$queryArguments = @()
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/filepool/templates/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.templates
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilepoolTemplate

function Get-isiFilesystemAccessTime{
<#
.SYNOPSIS
	Get Filesystem Access Time

.DESCRIPTION
	Retrieve settings for access time.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/filesystem/settings/access-time" -Cluster $Cluster
			return $ISIObject.access_time
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilesystemAccessTime

function Get-isiFilesystemCharacterEncoding{
<#
.SYNOPSIS
	Get Filesystem Character Encoding

.DESCRIPTION
	Retrieve current cluster character encoding settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/filesystem/settings/character-encodings" -Cluster $Cluster
			return $ISIObject.'character-encodings'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFilesystemCharacterEncoding

function Get-isiFsaPath{
<#
.SYNOPSIS
	Get Fsa Path

.DESCRIPTION
	Return export path as plain text.

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
			$ISIObject = Send-isiAPI -Method GET_JSON -Resource "/platform/1/fsa/path" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaPath

function Get-isiFsaResults{
<#
.SYNOPSIS
	Get Fsa Results

.DESCRIPTION
	List all results.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/fsa/results" -Cluster $Cluster
			return $ISIObject.results
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResults

function Get-isiFsaResult{
<#
.SYNOPSIS
	Get Fsa Result

.DESCRIPTION
	Retrieve result set information.

.PARAMETER id
	Result id

.PARAMETER name
	Result name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/fsa/results/$parameter1" -Cluster $Cluster
			return $ISIObject.results
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResult

function Get-isiFsaSettings{
<#
.SYNOPSIS
	Get Fsa Settings

.DESCRIPTION
	List all settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/fsa/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaSettings

function Get-isiJobEvents{
<#
.SYNOPSIS
	Get Job Events

.DESCRIPTION
	List job events.

.PARAMETER begin
	Restrict the query to events at or after the given time, in seconds since the Epoch.

.PARAMETER end
	Restrict the query to events before the given time, in seconds since the Epoch.

.PARAMETER job_id
	Restrict the query to the given job ID.

.PARAMETER job_type
	Restrict the query to the given job type.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER state
	Restrict the query to events containing the given state.
	Valid inputs: running,paused_user,paused_system,paused_policy,paused_priority,cancelled_user,cancelled_system,failed,succeeded,unknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$job_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$job_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('running','paused_user','paused_system','paused_policy','paused_priority','cancelled_user','cancelled_system','failed','succeeded','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($job_id){
				$queryArguments += 'job_id=' + $job_id
			}
			if ($job_type){
				$queryArguments += 'job_type=' + $job_type
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/job/events" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.events,$ISIObject.resume
			}else{
				return $ISIObject.events
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobEvents

function Get-isiJobSummary{
<#
.SYNOPSIS
	Get Job Summary

.DESCRIPTION
	View job engine status.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/job/job-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobSummary

function Get-isiJobs{
<#
.SYNOPSIS
	Get Jobs

.DESCRIPTION
	List running and paused jobs.

.PARAMETER batch
	If true, other arguments are ignored, and the query will return all results, unsorted, as quickly as possible.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER state
	Limit the results to jobs in the specified state.
	Valid inputs: running,paused_user,paused_system,paused_policy,paused_priority

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$batch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][ValidateSet('running','paused_user','paused_system','paused_policy','paused_priority')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($batch){
				$queryArguments += 'batch=' + $batch
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/job/jobs" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.jobs,$ISIObject.resume
			}else{
				return $ISIObject.jobs
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobs

function Get-isiJob{
<#
.SYNOPSIS
	Get Job

.DESCRIPTION
	View a single job instance.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/job/jobs/$parameter1" -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJob

function Get-isiJobPolicies{
<#
.SYNOPSIS
	Get Job Policies

.DESCRIPTION
	List job impact policies.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/job/policies" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.policies,$ISIObject.resume
			}else{
				return $ISIObject.policies
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobPolicies

function Get-isiJobPolicy{
<#
.SYNOPSIS
	Get Job Policy

.DESCRIPTION
	View a single job impact policy.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/job/policies/$parameter1" -Cluster $Cluster
			return $ISIObject.types
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobPolicy

function Get-isiJobReports{
<#
.SYNOPSIS
	Get Job Reports

.DESCRIPTION
	List job reports.

.PARAMETER begin
	Restrict the query to reports at or after the given time, in seconds since the Epoch.

.PARAMETER end
	Restrict the query to reports before the given time, in seconds since the Epoch.

.PARAMETER job_id
	Restrict the query to the given job ID.

.PARAMETER job_type
	Restrict the query to the given job type.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$job_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$job_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($job_id){
				$queryArguments += 'job_id=' + $job_id
			}
			if ($job_type){
				$queryArguments += 'job_type=' + $job_type
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/job/reports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobReports

function Get-isiJobStatistics{
<#
.SYNOPSIS
	Get Job Statistics

.DESCRIPTION
	View job engine statistics.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/job/statistics" -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobStatistics

function Get-isiJobTypes{
<#
.SYNOPSIS
	Get Job Types

.DESCRIPTION
	List job types.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER show_all
	Whether to show all job types, including hidden ones.  Defaults to false.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$show_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($show_all){
				$queryArguments += 'show_all=' + $show_all
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/job/types" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.types
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobTypes

function Get-isiJobType{
<#
.SYNOPSIS
	Get Job Type

.DESCRIPTION
	Retrieve job type information.

.PARAMETER id
	Type id

.PARAMETER name
	Type name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/job/types/$parameter1" -Cluster $Cluster
			return $ISIObject.types
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobType

function Get-isiEula{
<#
.SYNOPSIS
	Get Eula

.DESCRIPTION
	Retrieve the EULA as plain text.

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
			$ISIObject = Send-isiAPI -Method GET_JSON -Resource "/platform/1/license/eula" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEula

function Get-isiLicenses{
<#
.SYNOPSIS
	Get Licenses

.DESCRIPTION
	Retrieve license information for all licensable products.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/license/licenses" -Cluster $Cluster
			return $ISIObject.licenses
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiLicenses

function Get-isiLicense{
<#
.SYNOPSIS
	Get License

.DESCRIPTION
	Retrieve license information for the feature.

.PARAMETER id
	License id

.PARAMETER name
	License name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/license/licenses/$parameter1" -Cluster $Cluster
			return $ISIObject.licenses
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiLicense

function Get-isiHdfsProxyUsers{
<#
.SYNOPSIS
	Get Hdfs Proxyusers

.DESCRIPTION
	List all proxyusers.

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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/hdfs/proxyusers" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.proxyusers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsProxyUsers

function Get-isiHdfsProxyUser{
<#
.SYNOPSIS
	Get Hdfs Proxyuser

.DESCRIPTION
	List all proxyusers.

.PARAMETER id
	Proxyuser id

.PARAMETER name
	Proxyuser name

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
			$queryArguments = @()
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/hdfs/proxyusers/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.proxyusers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsProxyUser

function Get-isiHdfsProxyUserMembers{
<#
.SYNOPSIS
	Get Hdfs Proxyuser Members

.DESCRIPTION
	List all the members of the HDFS proxyuser.

.PARAMETER proxyuser_id
	Proxyuser proxyuser_id

.PARAMETER proxyuser_name
	Proxyuser proxyuser_name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$proxyuser_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$proxyuser_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('proxyuser_id')){
				$parameter1 = $proxyuser_id
			} else {
				$parameter1 = $proxyuser_name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1/members" -Cluster $Cluster
			return $ISIObject.members
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsProxyUserMembers

function Get-isiHdfsRacks{
<#
.SYNOPSIS
	Get Hdfs Racks

.DESCRIPTION
	List all racks.

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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/hdfs/racks" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.racks
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsRacks

function Get-isiHdfsRack{
<#
.SYNOPSIS
	Get Hdfs Rack

.DESCRIPTION
	Retrieve the HDFS rack.

.PARAMETER id
	Rack id

.PARAMETER name
	Rack name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/hdfs/racks/$parameter1" -Cluster $Cluster
			return $ISIObject.racks
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsRack

function Get-isiHdfsSettings{
<#
.SYNOPSIS
	Get Hdfs Settings

.DESCRIPTION
	Retrieve HDFS properties.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/hdfs/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsSettings

function Get-isiNfsCheck{
<#
.SYNOPSIS
	Get Nfs Check

.DESCRIPTION
	Retrieve NFS export validation information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/nfs/check" -Cluster $Cluster
			return $ISIObject.checks
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsCheck

function Get-isiNfsExports{
<#
.SYNOPSIS
	Get Nfs Exports

.DESCRIPTION
	List all NFS exports.

.PARAMETER check
	Check for conflicts when listing exports.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER scope
	If specified as effective or not specified, all export fields are shown.  If specified as user, only fields with non-default values are shown.
	Valid inputs: effective,user

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$check,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($check){
				$queryArguments += 'check=' + $check
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/exports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.exports,$ISIObject.resume
			}else{
				return $ISIObject.exports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExports

function Get-isiNfsExportsSummary{
<#
.SYNOPSIS
	Get Nfs Exports Summary

.DESCRIPTION
	Retrieve NFS export summary information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/nfs/exports-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExportsSummary

function Get-isiNfsExport{
<#
.SYNOPSIS
	Get Nfs Export

.DESCRIPTION
	Retrieve export information.

.PARAMETER id
	 id

.PARAMETER scope
	If specified as effective or not specified, all export fields are shown.  If specified as user, only fields with non-default values are shown.
	Valid inputs: effective,user

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			$parameter1 = $id
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/exports/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.exports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExport

function Get-isiNfsNlmLocks{
<#
.SYNOPSIS
	Get Nfs Nlm Locks

.DESCRIPTION
	List all NLM locks.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/nlm/locks" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.locks,$ISIObject.resume
			}else{
				return $ISIObject.locks
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmLocks

function Get-isiNfsNlmSessions{
<#
.SYNOPSIS
	Get Nfs Nlm Sessions

.DESCRIPTION
	List all NLM sessions.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/nlm/sessions" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.sessions,$ISIObject.resume
			}else{
				return $ISIObject.sessions
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmSessions

function Get-isiNfsNlmWaiters{
<#
.SYNOPSIS
	Get Nfs Nlm Waiters

.DESCRIPTION
	List all NLM lock waiters.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/nlm/waiters" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.waiters,$ISIObject.resume
			}else{
				return $ISIObject.waiters
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmWaiters

function Get-isiNfsSettingsExport{
<#
.SYNOPSIS
	Get Nfs Settings Export

.DESCRIPTION
	Retrieve export information.

.PARAMETER scope
	If specified as effective or not specified, all fields are returned.  If specified as user, only fields with non-default values are shown.  If specified as default, the original values are returned.
	Valid inputs: effective,user,default

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('effective','user','default')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/settings/export" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsSettingsExport

function Get-isiNfsSettingsGlobal{
<#
.SYNOPSIS
	Get Nfs Settings Global

.DESCRIPTION
	Retrieve the NFS configuration.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/nfs/settings/global" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsSettingsGlobal

function Get-isiSmbOpenfiles{
<#
.SYNOPSIS
	Get Smb Openfiles

.DESCRIPTION
	List open files.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	Order results by this field. Default is id.
	Valid inputs: id,file,user,locks

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('id','file','user','locks')][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/smb/openfiles" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.openfiles,$ISIObject.resume
			}else{
				return $ISIObject.openfiles
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbOpenfiles

function Get-isiSmbSessions{
<#
.SYNOPSIS
	Get Smb Sessions

.DESCRIPTION
	List open sessions.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	Order results by this field.
	Valid inputs: computer,user,client_type,openfiles,active_time,idle_time,guest_login,encryption

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('computer','user','client_type','openfiles','active_time','idle_time','guest_login','encryption')][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/smb/sessions" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.sessions,$ISIObject.resume
			}else{
				return $ISIObject.sessions
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSessions

function Get-isiSmbSettingsGlobal{
<#
.SYNOPSIS
	Get Smb Settings Global

.DESCRIPTION
	List all settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/smb/settings/global" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSettingsGlobal

function Get-isiSmbSettingsShare{
<#
.SYNOPSIS
	Get Smb Settings Share

.DESCRIPTION
	List all settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER zone
	Zone which contains these share settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/smb/settings/share" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSettingsShare

function Get-isiSmbShares{
<#
.SYNOPSIS
	Get Smb Shares

.DESCRIPTION
	List all shares.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resolve_names
	If true, resolve group and user names in personas.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER sort
	Order results by this field. Default is id.
	Valid inputs: id,name,path,description

.PARAMETER zone
	Zone which contains this share.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][ValidateSet('id','name','path','description')][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/smb/shares" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.shares,$ISIObject.resume
			}else{
				return $ISIObject.shares
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbShares

function Get-isiSmbSharesSummary{
<#
.SYNOPSIS
	Get Smb Shares Summary

.DESCRIPTION
	Return summary information about shares.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/protocols/smb/shares-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSharesSummary

function Get-isiSmbShare{
<#
.SYNOPSIS
	Get Smb Share

.DESCRIPTION
	Retrieve share.

.PARAMETER id
	Share id

.PARAMETER name
	Share name

.PARAMETER resolve_names
	If true, resolve group and user names in personas.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER zone
	Zone which contains this share.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/smb/shares/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.shares
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbShare

function Get-isiQuotaLicense{
<#
.SYNOPSIS
	Get Quota License

.DESCRIPTION
	Retrieve license information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/license" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaLicense

function Get-isiQuotas{
<#
.SYNOPSIS
	Get Quotas

.DESCRIPTION
	List all or matching quotas. Can also be used to retrieve quota state from existing reports. For any query argument not supplied, the default behavior is return all.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER enforced
	Only list quotas with this enforcement (non-accounting).

.PARAMETER exceeded
	Set to true to only list quotas which have exceeded one or more of their thresholds.

.PARAMETER include_snapshots
	Only list quotas with this setting for include_snapshots.

.PARAMETER path
	Only list quotas matching this path (see also recurse_path_*).

.PARAMETER persona
	Only list user or group quotas matching this persona (must be used with the corresponding type argument).  Format is <PERSONA_TYPE>:<string/integer>, where PERSONA_TYPE is one of USER, GROUP, SID, ID, or GID.

.PARAMETER recurse_path_children
	If used with the path argument, match all quotas at that path or any descendent sub-directory.

.PARAMETER recurse_path_parents
	If used with the path argument, match all quotas at that path or any parent directory.

.PARAMETER report_id
	Use the named report as a source rather than the live quotas. See the /q/quota/reports resource for a list of valid reports.

.PARAMETER resolve_names
	If true, resolve group and user names in personas.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER type
	Only list quotas matching this type.
	Valid inputs: directory,user,group,default-user,default-group

.PARAMETER zone
	Optional named zone to use for user and group resolution.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$enforced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$exceeded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$include_snapshots,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$persona,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][bool]$recurse_path_children,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][bool]$recurse_path_parents,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$report_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][ValidateSet('directory','user','group','default-user','default-group')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($enforced){
				$queryArguments += 'enforced=' + $enforced
			}
			if ($exceeded){
				$queryArguments += 'exceeded=' + $exceeded
			}
			if ($include_snapshots){
				$queryArguments += 'include_snapshots=' + $include_snapshots
			}
			if ($path){
				$queryArguments += 'path=' + $path
			}
			if ($persona){
				$queryArguments += 'persona=' + $persona
			}
			if ($recurse_path_children){
				$queryArguments += 'recurse_path_children=' + $recurse_path_children
			}
			if ($recurse_path_parents){
				$queryArguments += 'recurse_path_parents=' + $recurse_path_parents
			}
			if ($report_id){
				$queryArguments += 'report_id=' + $report_id
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/quota/quotas" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.quotas,$ISIObject.resume
			}else{
				return $ISIObject.quotas
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotas

function Get-isiQuotasSummary{
<#
.SYNOPSIS
	Get Quotas Summary

.DESCRIPTION
	Return summary information about quotas.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/quotas-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotasSummary

function Get-isiQuota{
<#
.SYNOPSIS
	Get Quota

.DESCRIPTION
	Retrieve quota information.

.PARAMETER id
	Quota id

.PARAMETER name
	Quota name

.PARAMETER resolve_names
	If true, resolve group and user names in personas.

.PARAMETER zone
	Optional named zone to use for user and group resolution.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/quota/quotas/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.quotas
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuota

function Get-isiQuotaNotifications{
<#
.SYNOPSIS
	Get Quota Notifications

.DESCRIPTION
	List all rules.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('quota_id')){
				$parameter1 = $quota_id
			} else {
				$parameter1 = $quota_name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/quotas/$parameter1/notifications" -Cluster $Cluster
			return $ISIObject.notifications
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaNotifications

function Get-isiQuotaNotification{
<#
.SYNOPSIS
	Get Quota Notification

.DESCRIPTION
	Retrieve notification rule information.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('quota_id')){
				$parameter1 = $quota_id
			} else {
				$parameter1 = $quota_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/quotas/$parameter1/notifications/$parameter2" -Cluster $Cluster
			return $ISIObject.notifications
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaNotification

function Get-isiQuotaReports{
<#
.SYNOPSIS
	Get Quota Reports

.DESCRIPTION
	List all or matching reports.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER generated
	Only list reports matching this source.
	Valid inputs: manual,scheduled,all

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	Order results by this field.
	Valid inputs: time,generated,type

.PARAMETER type
	Only list reports matching this type.
	Valid inputs: summary,detail,all

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('manual','scheduled','all')][string]$generated,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('time','generated','type')][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][ValidateSet('summary','detail','all')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($generated){
				$queryArguments += 'generated=' + $generated
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/quota/reports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaReports

function Get-isiQuotaReport{
<#
.SYNOPSIS
	Get Quota Report

.DESCRIPTION
	Retrieve report data (XML) or contents (meta-data).

.PARAMETER id
	Report id

.PARAMETER name
	Report name

.PARAMETER contents
	Display JSON meta-data contents instead of report data.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$contents,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($contents){
				$queryArguments += 'contents=' + $contents
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/quota/reports/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaReport

function Get-isiQuotaReportAbout{
<#
.SYNOPSIS
	Get Quota Report About

.DESCRIPTION
	Retrieve report meta-data information.

.PARAMETER id
	Report id

.PARAMETER name
	Report name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/reports/$parameter1/about" -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaReportAbout

function Get-isiQuotaSettingsMappings{
<#
.SYNOPSIS
	Get Quota Settings Mappings

.DESCRIPTION
	List all rules.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/settings/mappings" -Cluster $Cluster
			return $ISIObject.mappings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaSettingsMappings

function Get-isiQuotaSettingsMapping{
<#
.SYNOPSIS
	Get Quota Settings Mapping

.DESCRIPTION
	Retrieve the mapping information.

.PARAMETER id
	Quota id

.PARAMETER name
	Quota name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/settings/mappings/$parameter1" -Cluster $Cluster
			return $ISIObject.mappings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaSettingsMapping

function Get-isiQuotaSettingsNotifications{
<#
.SYNOPSIS
	Get Quota Settings Notifications

.DESCRIPTION
	List all rules.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/settings/notifications" -Cluster $Cluster
			return $ISIObject.notifications
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaSettingsNotifications

function Get-isiQuotaSettingsNotification{
<#
.SYNOPSIS
	Get Quota Settings Notification

.DESCRIPTION
	Retrieve notification rule information.

.PARAMETER id
	Notification id

.PARAMETER name
	Notification name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/settings/notifications/$parameter1" -Cluster $Cluster
			return $ISIObject.notifications
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaSettingsNotification

function Get-isiQuotaSettingsReports{
<#
.SYNOPSIS
	Get Quota Settings Reports

.DESCRIPTION
	List all settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/quota/settings/reports" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiQuotaSettingsReports

function Get-isiRemoteSupport{
<#
.SYNOPSIS
	Get Remote Support

.DESCRIPTION
	List all settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/remotesupport/connectemc" -Cluster $Cluster
			return $ISIObject.connectemc
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiRemoteSupport

function Get-isiSnapshotAliases{
<#
.SYNOPSIS
	Get Snapshot Aliases

.DESCRIPTION
	List all or matching snapshot aliases.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.  Choices are id, name, snapshot, and created.  Default is id.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/snapshot/aliases" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.aliases,$ISIObject.resume
			}else{
				return $ISIObject.aliases
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotAliases

function Get-isiSnapshotAlias{
<#
.SYNOPSIS
	Get Snapshot Aliase

.DESCRIPTION
	Retrieve snapshot alias information.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/aliases/$parameter1" -Cluster $Cluster
			return $ISIObject.aliases
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotAlias

function Get-isiSnapshotChangelists{
<#
.SYNOPSIS
	Get Snapshot Changelists

.DESCRIPTION
	List all changelists.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/changelists" -Cluster $Cluster
			return $ISIObject.changelists
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotChangelists

function Get-isiSnapshotChangelist{
<#
.SYNOPSIS
	Get Snapshot Changelist

.DESCRIPTION
	Retrieve basic information on a changelist.

.PARAMETER id
	Changelist id

.PARAMETER name
	Changelist name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/changelists/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotChangelist

function Get-isiSnapshotChangelistLins{
<#
.SYNOPSIS
	Get Snapshot Changelist Lins

.DESCRIPTION
	Get entries from a changelist.

.PARAMETER changelist_id
	Changelist changelist_id

.PARAMETER changelist_name
	Changelist changelist_name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$changelist_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$changelist_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('changelist_id')){
				$parameter1 = $changelist_id
			} else {
				$parameter1 = $changelist_name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/changelists/$parameter1/lins" -Cluster $Cluster
			return $ISIObject.lins
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotChangelistLins

function Get-isiSnapshotChangelistLin{
<#
.SYNOPSIS
	Get Snapshot Changelist Lins

.DESCRIPTION
	Get a single entry from the changelist.

.PARAMETER changelist_id
	Changelist changelist_id

.PARAMETER changelist_name
	Changelist changelist_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$changelist_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$changelist_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('changelist_id')){
				$parameter1 = $changelist_id
			} else {
				$parameter1 = $changelist_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/changelists/$parameter1/lins/$parameter2" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotChangelistLin

function Get-isiSnapshotLicense{
<#
.SYNOPSIS
	Get Snapshot License

.DESCRIPTION
	Retrieve license information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/license" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotLicense

function Get-isiSnapshotPending{
<#
.SYNOPSIS
	Get Snapshot Pending

.DESCRIPTION
	Return list of snapshots to be taken.

.PARAMETER begin
	Unix Epoch time to start generating matches. Default is now.

.PARAMETER end
	Unix Epoch time to end generating matches. Default is forever.

.PARAMETER limit
	Return no more than this many result at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER schedule
	Limit output only to the named schedule.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($schedule){
				$queryArguments += 'schedule=' + $schedule
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/snapshot/pending" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.pending,$ISIObject.resume
			}else{
				return $ISIObject.pending
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotPending

function Get-isiSnapshotRepstates{
<#
.SYNOPSIS
	Get Snapshot Repstates

.DESCRIPTION
	List all repstates.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/repstates" -Cluster $Cluster
			return $ISIObject.repstates
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotRepstates

function Get-isiSnapshotRepstate{
<#
.SYNOPSIS
	Get Snapshot Repstate

.DESCRIPTION
	Retrieve basic information on a repstate.

.PARAMETER id
	Repstate id

.PARAMETER name
	Repstate name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/repstates/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotRepstate

function Get-isiSnapshotSchedules{
<#
.SYNOPSIS
	Get Snapshot Schedules

.DESCRIPTION
	List all or matching schedules.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.  Choices are id, name, path, pattern, schedule, duration, alias, next_run, and next_snapshot.  Default is id.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/snapshot/schedules" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.schedules,$ISIObject.resume
			}else{
				return $ISIObject.schedules
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotSchedules

function Get-isiSnapshotSchedule{
<#
.SYNOPSIS
	Get Snapshot Schedule

.DESCRIPTION
	Retrieve the schedule.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/schedules/$parameter1" -Cluster $Cluster
			return $ISIObject.schedules
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotSchedule

function Get-isiSnapshotSettings{
<#
.SYNOPSIS
	Get Snapshot Settings

.DESCRIPTION
	List all settings

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotSettings

function Get-isiSnapshots{
<#
.SYNOPSIS
	Get Snapshots

.DESCRIPTION
	List all or matching snapshots.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER schedule
	Only list snapshots created by this schedule.

.PARAMETER sort
	The field that will be used for sorting.  Choices are id, name, path, created, expires, size, has_locks, schedule, alias_target, alias_target_name, pct_filesystem, pct_reserve, and state.  Default is id.

.PARAMETER state
	Only list snapshots matching this state.
	Valid inputs: all,active,deleting

.PARAMETER type
	Only list snapshots matching this type.
	Valid inputs: all,alias,real

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][ValidateSet('all','active','deleting')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('all','alias','real')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($schedule){
				$queryArguments += 'schedule=' + $schedule
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/snapshot/snapshots" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.snapshots,$ISIObject.resume
			}else{
				return $ISIObject.snapshots
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshots

function Get-isiSnapshotsSummary{
<#
.SYNOPSIS
	Get Snapshots Summary

.DESCRIPTION
	Return summary information about snapshots.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/snapshots-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotsSummary

function Get-isiSnapshot{
<#
.SYNOPSIS
	Get Snapshot

.DESCRIPTION
	Retrieve snapshot information.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/snapshots/$parameter1" -Cluster $Cluster
			return $ISIObject.snapshots
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshot

function Get-isiSnapshotLocks{
<#
.SYNOPSIS
	Get Snapshot Locks

.DESCRIPTION
	List all locks.

.PARAMETER snapshot_id
	Snapshot snapshot_id

.PARAMETER snapshot_name
	Snapshot snapshot_name

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.  Choices are id, expires, and comment.  Default is id.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($psBoundParameters.ContainsKey('snapshot_id')){
				$parameter1 = $snapshot_id
			} else {
				$parameter1 = $snapshot_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/snapshot/snapshots/$parameter1/locks" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.locks,$ISIObject.resume
			}else{
				return $ISIObject.locks
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotLocks

function Get-isiSnapshotLock{
<#
.SYNOPSIS
	Get Snapshot Lock

.DESCRIPTION
	Retrieve lock information.

.PARAMETER snapshot_id
	Snapshot snapshot_id

.PARAMETER snapshot_name
	Snapshot snapshot_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('snapshot_id')){
				$parameter1 = $snapshot_id
			} else {
				$parameter1 = $snapshot_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/snapshot/snapshots/$parameter1/locks/$parameter2" -Cluster $Cluster
			return $ISIObject.locks
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotLock

function Get-isiStatisticsCurrent{
<#
.SYNOPSIS
	Get Statistics Current

.DESCRIPTION
	Retrieve stats.

.PARAMETER degraded
	If true, try to continue even if some stats are unavailable. In this case, errors will be present in the per-key returned data.

.PARAMETER devid
	Node devid to query.  Either an <integer> or "all".  Can be used more than one time to query multiple nodes.  "all" queries all up nodes. 0 means query the local node. For "cluster" scoped keys, in any devid including 0 can be used.

.PARAMETER expand_clientid
	If true, use name resolution to expand client addresses and other IDs.

.PARAMETER key
	Key names. Can be used more than one time to query multiple keys.

.PARAMETER timeout
	Time in seconds to wait for results from remote nodes.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][array]$devid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$expand_clientid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][array]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($devid){
				$queryArguments += 'devid=' + $devid
			}
			if ($expand_clientid){
				$queryArguments += 'expand_clientid=' + $expand_clientid
			}
			if ($key){
				$queryArguments += 'key=' + $key
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/statistics/current" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.stats
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsCurrent

function Get-isiStatisticsHistory{
<#
.SYNOPSIS
	Get Statistics History

.DESCRIPTION
	Retrieve stats.

.PARAMETER begin
	Earliest time (Unix epoch seconds) of interest. Negative times are interpreted as relative (before) now.

.PARAMETER degraded
	If true, try to continue even if some stats are unavailable. In this case, errors will be present in the per-key returned data.

.PARAMETER devid
	Node devid to query.  Either an <integer> or "all".  Can be used more than one time to query multiple nodes.  "all" queries all up nodes. 0 means query the local node. For "cluster" scoped keys, in any devid including 0 can be used.

.PARAMETER end
	Latest time (Unix epoch seconds) of interest. Negative times are interpreted as relative (before) now. If not supplied, use now as the end time.

.PARAMETER expand_clientid
	If true, use name resolution to expand client addresses and other IDs.

.PARAMETER interval
	Minimum sampling interval time in seconds.  If native statistics are higher resolution, data will be down-sampled.

.PARAMETER key
	Key names. Can be used more than one time to query multiple keys.

.PARAMETER memory_only
	Only use statistics sources that reside in memory (faster, but with less retention).

.PARAMETER timeout
	Time in seconds to wait for results from remote nodes.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][array]$devid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][bool]$expand_clientid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][int]$interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][array]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][bool]$memory_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($devid){
				$queryArguments += 'devid=' + $devid
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($expand_clientid){
				$queryArguments += 'expand_clientid=' + $expand_clientid
			}
			if ($interval){
				$queryArguments += 'interval=' + $interval
			}
			if ($key){
				$queryArguments += 'key=' + $key
			}
			if ($memory_only){
				$queryArguments += 'memory_only=' + $memory_only
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/statistics/history" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.stats
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsHistory

function Get-isiStatisticsKeys{
<#
.SYNOPSIS
	Get Statistics Keys

.DESCRIPTION
	List meta-data for matching keys.

.PARAMETER count
	Only count matching keys, do not return meta-data.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER queryable
	Only list keys that can/cannot be queries. Default is true.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$queryable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($count){
				$queryArguments += 'count=' + $count
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($queryable){
				$queryArguments += 'queryable=' + $queryable
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/statistics/keys" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.keys,$ISIObject.resume
			}else{
				return $ISIObject.keys
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsKeys

function Get-isiStatisticsKey{
<#
.SYNOPSIS
	Get Statistics Key

.DESCRIPTION
	List key meta-data.

.PARAMETER id
	Key id

.PARAMETER name
	Key name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/statistics/keys/$parameter1" -Cluster $Cluster
			return $ISIObject.keys
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsKey

function Get-isiStatisticsProtocols{
<#
.SYNOPSIS
	Get Statistics Protocols

.DESCRIPTION
	Retrieve protocol list.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/statistics/protocols" -Cluster $Cluster
			return $ISIObject.protocols
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsProtocols

function Get-isiStoragepoolCompatibilitiesClassActive{
<#
.SYNOPSIS
	Get Storagepool Compatibilities Class Active

.DESCRIPTION
	Get a list of active compatibilities

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/compatibilities/class/active" -Cluster $Cluster
			return $ISIObject.active
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesClassActive

function Get-isiStoragepoolCompatibilitiesClassActiveId{
<#
.SYNOPSIS
	Get Storagepool Compatibilities Class Active ID

.DESCRIPTION
	Get an active compatibilities by id

.PARAMETER id
	Active Class id

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/compatibilities/class/active/<ID>" -Cluster $Cluster
			return $ISIObject.active
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesClassActiveId

function Get-isiStoragepoolCompatibilitiesClassAvailable{
<#
.SYNOPSIS
	Get Storagepool Compatibilities Class Available

.DESCRIPTION
	Get a list of available compatibilities

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/compatibilities/class/available" -Cluster $Cluster
			return $ISIObject.available
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesClassAvailable

function Get-isiStoragepoolCompatibilitiesSSDActive{
<#
.SYNOPSIS
	Get Storagepool Compatibilities SSD Active

.DESCRIPTION
	Get a list of active ssd compatibilities

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/compatibilities/ssd/active" -Cluster $Cluster
			return $ISIObject.active
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDActive

function Get-isiStoragepoolCompatibilitiesSSDActiveId{
<#
.SYNOPSIS
	Get Storagepool Compatibilities SSD Active ID

.DESCRIPTION
	Get a active ssd compatibilities by id

.PARAMETER id
	Active SSD id

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/compatibilities/ssd/active/<ID>" -Cluster $Cluster
			return $ISIObject.active
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDActiveId

function Get-isiStoragepoolCompatibilitiesSSDAvailable{
<#
.SYNOPSIS
	Get Storagepool Compatibilities SSD Available

.DESCRIPTION
	Get a list of available ssd compatibilities

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/compatibilities/ssd/available" -Cluster $Cluster
			return $ISIObject.available
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDAvailable

function Get-isiStoragepoolNodepools{
<#
.SYNOPSIS
	Get Storagepool Nodepools

.DESCRIPTION
	List all node pools.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/nodepools" -Cluster $Cluster
			return $ISIObject.nodepools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolNodepools

function Get-isiStoragepoolNodepool{
<#
.SYNOPSIS
	Get Storagepool Nodepool

.DESCRIPTION
	Retrieve node pool information.

.PARAMETER id
	Nodepool id

.PARAMETER name
	Nodepool name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/nodepools/$parameter1" -Cluster $Cluster
			return $ISIObject.nodepools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolNodepool

function Get-isiStoragepoolSettings{
<#
.SYNOPSIS
	Get Storagepool Settings

.DESCRIPTION
	List all settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolSettings

function Get-isiStoragepoolStatus{
<#
.SYNOPSIS
	Get Storagepool Status

.DESCRIPTION
	List any health conditions detected.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/status" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolStatus

function Get-isiStoragepools{
<#
.SYNOPSIS
	Get Storagepools

.DESCRIPTION
	List all storage pools.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/storagepools" -Cluster $Cluster
			return $ISIObject.storagepools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepools

function Get-isiStoragepoolSuggestedProtection{
<#
.SYNOPSIS
	Get Storagepool Suggested Protection

.DESCRIPTION
	Retrieve the suggested protection policy.

.PARAMETER id
	Nodepool id

.PARAMETER name
	Nodepool name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/suggested_protection/$parameter1" -Cluster $Cluster
			return $ISIObject.suggested_protection
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolSuggestedProtection

function Get-isiStoragepoolTiers{
<#
.SYNOPSIS
	Get Storagepool Tiers

.DESCRIPTION
	List all tiers.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/tiers" -Cluster $Cluster
			return $ISIObject.tiers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolTiers

function Get-isiStoragepoolTier{
<#
.SYNOPSIS
	Get Storagepool Tier

.DESCRIPTION
	Retrieve tier information.

.PARAMETER id
	Tier id

.PARAMETER name
	Tier name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/tiers/$parameter1" -Cluster $Cluster
			return $ISIObject.tiers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolTier

function Get-isiStoragepoolUnprovisioned{
<#
.SYNOPSIS
	Get Storagepool Unprovisioned

.DESCRIPTION
	Get the uprovisioned nodes and drives

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/storagepool/unprovisioned" -Cluster $Cluster
			return $ISIObject.unprovisioned
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolUnprovisioned

function Get-isiSyncHistoryFile{
<#
.SYNOPSIS
	Get Sync History File

.DESCRIPTION
	List file operations performance data.

.PARAMETER begin
	Begin timestamp for time-series report.

.PARAMETER end
	End timestamp for time-series report.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/history/file" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.statistics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncHistoryFile

function Get-isiSyncHistoryNetwork{
<#
.SYNOPSIS
	Get Sync History Network

.DESCRIPTION
	List network operations performance data.

.PARAMETER begin
	Begin timestamp for time-series report.

.PARAMETER end
	End timestamp for time-series report.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/history/network" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.statistics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncHistoryNetwork

function Get-isiSyncJobs{
<#
.SYNOPSIS
	Get Sync Jobs

.DESCRIPTION
	Get a list of SyncIQ jobs.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER state
	The state of the job.
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,unknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/jobs" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.jobs,$ISIObject.resume
			}else{
				return $ISIObject.jobs
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncJobs

function Get-isiSyncJob{
<#
.SYNOPSIS
	Get Sync Job

.DESCRIPTION
	View a single SyncIQ job.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/jobs/$parameter1" -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncJob

function Get-isiSyncLicense{
<#
.SYNOPSIS
	Get Sync License

.DESCRIPTION
	Retrieve license information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/license" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncLicense

function Get-isiSyncPolicies{
<#
.SYNOPSIS
	Get Sync Policies

.DESCRIPTION
	List all SyncIQ policies.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER summary
	Show only summary properties

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$summary,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($summary){
				$queryArguments += 'summary=' + $summary
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/policies" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.policies,$ISIObject.resume
			}else{
				return $ISIObject.policies
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncPolicies

function Get-isiSyncPolicy{
<#
.SYNOPSIS
	Get Sync Policy

.DESCRIPTION
	View a single SyncIQ policy.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/policies/$parameter1" -Cluster $Cluster
			return $ISIObject.policies
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncPolicy

function Get-isiSyncReports{
<#
.SYNOPSIS
	Get Sync Reports

.DESCRIPTION
	Get a list of SyncIQ reports.  By default 10 reports are returned per policy, unless otherwise specified by 'reports_per_policy'.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER newer_than
	Filter the returned reports to include only those whose jobs started more recently than the specified number of days ago.

.PARAMETER policy_name
	Filter the returned reports to include only those with this policy name.

.PARAMETER reports_per_policy
	If specified, only the N most recent reports will be returned per policy.  If no other query args are present this argument defaults to 10. 

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER state
	Filter the returned reports to include only those whose jobs are in this state.
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,unknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$newer_than,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$policy_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$reports_per_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($newer_than){
				$queryArguments += 'newer_than=' + $newer_than
			}
			if ($policy_name){
				$queryArguments += 'policy_name=' + $policy_name
			}
			if ($reports_per_policy){
				$queryArguments += 'reports_per_policy=' + $reports_per_policy
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/reports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncReports

function Get-isiSyncReportsRotate{
<#
.SYNOPSIS
	Get Sync Reports Rotate

.DESCRIPTION
	Whether the rotation is still running or not.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/reports-rotate" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncReportsRotate

function Get-isiSyncReport{
<#
.SYNOPSIS
	Get Sync Report

.DESCRIPTION
	View a single SyncIQ report.

.PARAMETER id
	Rid id

.PARAMETER name
	Rid name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/reports/$parameter1" -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncReport

function Get-isiSyncReportSubreports{
<#
.SYNOPSIS
	Get Sync Report Subreports

.DESCRIPTION
	Get a list of SyncIQ subreports for a report.

.PARAMETER report_id
	Report report_id

.PARAMETER report_name
	Report report_name

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER newer_than
	Filter the returned reports to include only those whose jobs started more recently than the specified number of days ago.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER state
	Filter the returned reports to include only those whose jobs are in this state.
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,unknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$report_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$report_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$newer_than,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($newer_than){
				$queryArguments += 'newer_than=' + $newer_than
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($psBoundParameters.ContainsKey('report_id')){
				$parameter1 = $report_id
			} else {
				$parameter1 = $report_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/reports/$parameter1/subreports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.subreports,$ISIObject.resume
			}else{
				return $ISIObject.subreports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncReportSubreports

function Get-isiSyncReportSubreport{
<#
.SYNOPSIS
	Get Sync Report Subreport

.DESCRIPTION
	View a single SyncIQ subreport.

.PARAMETER report_id
	Report report_id

.PARAMETER report_name
	Report report_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$report_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$report_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('report_id')){
				$parameter1 = $report_id
			} else {
				$parameter1 = $report_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/reports/$parameter1/subreports/$parameter2" -Cluster $Cluster
			return $ISIObject.subreports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncReportSubreport

function Get-isiSyncRules{
<#
.SYNOPSIS
	Get Sync Rules

.DESCRIPTION
	List all SyncIQ performance rules.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER type
	Filter the returned rules to include only those with this rule type.
	Valid inputs: bandwidth,file_count,cpu

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('bandwidth','file_count','cpu')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/rules" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.rules,$ISIObject.resume
			}else{
				return $ISIObject.rules
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncRules

function Get-isiSyncRule{
<#
.SYNOPSIS
	Get Sync Rule

.DESCRIPTION
	View a single SyncIQ performance rule.

.PARAMETER id
	Rule id

.PARAMETER name
	Rule name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/rules/$parameter1" -Cluster $Cluster
			return $ISIObject.rules
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncRule

function Get-isiSyncSettings{
<#
.SYNOPSIS
	Get Sync Settings

.DESCRIPTION
	Retrieve the global SyncIQ settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncSettings

function Get-isiSyncTargetPolicies{
<#
.SYNOPSIS
	Get Sync Target Policies

.DESCRIPTION
	List all SyncIQ target policies.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER target_path
	Filter the returned policies to include only those with this target path.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($target_path){
				$queryArguments += 'target_path=' + $target_path
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/target/policies" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.policies,$ISIObject.resume
			}else{
				return $ISIObject.policies
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncTargetPolicies

function Get-isiSyncTargetPolicy{
<#
.SYNOPSIS
	Get Sync Target Policy

.DESCRIPTION
	View a single SyncIQ target policy.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/target/policies/$parameter1" -Cluster $Cluster
			return $ISIObject.policies
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncTargetPolicy

function Get-isiSyncTargetReports{
<#
.SYNOPSIS
	Get Sync Target Reports

.DESCRIPTION
	Get a list of SyncIQ target reports.  By default 10 reports are returned per policy, unless otherwise specified by 'reports_per_policy'.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER newer_than
	Filter the returned reports to include only those whose jobs started more recently than the specified number of days ago.

.PARAMETER policy_name
	Filter the returned reports to include only those with this policy name.

.PARAMETER reports_per_policy
	If specified, only the N most recent reports will be returned per policy.  If no other query args are present this argument defaults to 10. 

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER state
	Filter the returned reports to include only those whose jobs are in this state.
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,unknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$newer_than,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$policy_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$reports_per_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($newer_than){
				$queryArguments += 'newer_than=' + $newer_than
			}
			if ($policy_name){
				$queryArguments += 'policy_name=' + $policy_name
			}
			if ($reports_per_policy){
				$queryArguments += 'reports_per_policy=' + $reports_per_policy
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/target/reports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncTargetReports

function Get-isiSyncTargetReport{
<#
.SYNOPSIS
	Get Sync Target Report

.DESCRIPTION
	View a single SyncIQ target report.

.PARAMETER id
	Report id

.PARAMETER name
	Report name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/target/reports/$parameter1" -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncTargetReport

function Get-isiSyncTargetReportSubreports{
<#
.SYNOPSIS
	Get Sync Target Report Subreports

.DESCRIPTION
	Get a list of SyncIQ target subreports for a report.

.PARAMETER report_id
	Report report_id

.PARAMETER report_name
	Report report_name

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER newer_than
	Filter the returned reports to include only those whose jobs started more recently than the specified number of days ago.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER state
	Filter the returned reports to include only those whose jobs are in this state.
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,unknown

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$report_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$report_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$newer_than,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($newer_than){
				$queryArguments += 'newer_than=' + $newer_than
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($state){
				$queryArguments += 'state=' + $state
			}
			if ($psBoundParameters.ContainsKey('report_id')){
				$parameter1 = $report_id
			} else {
				$parameter1 = $report_name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/sync/target/reports/$parameter1/subreports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.subreports,$ISIObject.resume
			}else{
				return $ISIObject.subreports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncTargetReportSubreports

function Get-isiSyncTargetReportSubreport{
<#
.SYNOPSIS
	Get Sync Target Report Subreport

.DESCRIPTION
	View a single SyncIQ target subreport.

.PARAMETER report_id
	Report report_id

.PARAMETER report_name
	Report report_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$report_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$report_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('report_id')){
				$parameter1 = $report_id
			} else {
				$parameter1 = $report_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/sync/target/reports/$parameter1/subreports/$parameter2" -Cluster $Cluster
			return $ISIObject.subreports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncTargetReportSubreport

function Get-isiWormDomains{
<#
.SYNOPSIS
	Get Worm Domains

.DESCRIPTION
	List all WORM domains.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/worm/domains" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.domains,$ISIObject.resume
			}else{
				return $ISIObject.domains
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiWormDomains

function Get-isiWormDomain{
<#
.SYNOPSIS
	Get Worm Domain

.DESCRIPTION
	View a single WORM domain.

.PARAMETER id
	Domain id

.PARAMETER name
	Domain name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/worm/domains/$parameter1" -Cluster $Cluster
			return $ISIObject.domains
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiWormDomain

function Get-isiWormSettings{
<#
.SYNOPSIS
	Get Worm Settings

.DESCRIPTION
	Get the global WORM settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/worm/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiWormSettings

function Get-isiZones{
<#
.SYNOPSIS
	Get Zones

.DESCRIPTION
	List all access zones.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/zones" -Cluster $Cluster
			return $ISIObject.zones
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiZones

function Get-isiZonesSummary{
<#
.SYNOPSIS
	Get Zones Summary

.DESCRIPTION
	Retrieve access zone summary information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/zones-summary" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiZonesSummary

function Get-isiZoneSummary{
<#
.SYNOPSIS
	Get Zone Summary

.DESCRIPTION
	Retrieve non-privileged access zone information.

.PARAMETER id
	Zone id

.PARAMETER name
	Zone name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/zones-summary/$parameter1" -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiZoneSummary

function Get-isiZone{
<#
.SYNOPSIS
	Get Zone

.DESCRIPTION
	Retrieve the access zone information.

.PARAMETER id
	Zone id

.PARAMETER name
	Zone name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/zones/$parameter1" -Cluster $Cluster
			return $ISIObject.zones
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiZone

function Get-isiClusterExternalIPsV2{
<#
.SYNOPSIS
	Get Cluster External IPs

.DESCRIPTION
	Retrieve the cluster IP addresses including IPV4 and IPV6.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/2/cluster/external-ips" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterExternalIPsV2

function Get-isiEventsV2{
<#
.SYNOPSIS
	Get Events

.DESCRIPTION
	Retrieve event information.

.PARAMETER acknowledged
	If true, only return events that have been acknowledged.

.PARAMETER begin
	Specifies the earliest time to query events from.

.PARAMETER coalesced
	If true, only return events that have been coalesced.

.PARAMETER coalescing
	If true, only return coalescing events.

.PARAMETER count
	If true, return a count of events.

.PARAMETER devid
	Specifies the devid of events to query for.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER end
	Specifies the latest time to query events from.

.PARAMETER ended
	If true, only return events that have ended.

.PARAMETER event_type
	Specifies the event_id of events to query for.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER severity
	Specifies the severity of events to query for.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$acknowledged,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$coalesced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$coalescing,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][bool]$count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][array]$devid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][bool]$ended,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][array]$event_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][array]$severity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($acknowledged){
				$queryArguments += 'acknowledged=' + $acknowledged
			}
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($coalesced){
				$queryArguments += 'coalesced=' + $coalesced
			}
			if ($coalescing){
				$queryArguments += 'coalescing=' + $coalescing
			}
			if ($count){
				$queryArguments += 'count=' + $count
			}
			if ($devid){
				$queryArguments += 'devid=' + $devid
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($ended){
				$queryArguments += 'ended=' + $ended
			}
			if ($event_type){
				$queryArguments += 'event_type=' + $event_type
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($severity){
				$queryArguments += 'severity=' + $severity
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/event/events" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.events,$ISIObject.resume
			}else{
				return $ISIObject.events
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventsV2

function Get-isiEventV2{
<#
.SYNOPSIS
	Get Event

.DESCRIPTION
	Retrieve event information.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/2/event/events/$parameter1" -Cluster $Cluster
			return $ISIObject.events
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventV2

function Get-isiNfsAliasesV2{
<#
.SYNOPSIS
	Get Nfs Aliases

.DESCRIPTION
	List all NFS aliases.

.PARAMETER check
	Check for conflicts when listing exports.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$check,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($check){
				$queryArguments += 'check=' + $check
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/aliases" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.aliases,$ISIObject.resume
			}else{
				return $ISIObject.aliases
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsAliasesV2

function Get-isiNfsAliasV2{
<#
.SYNOPSIS
	Get Nfs Aliase

.DESCRIPTION
	Retrieve export information.

.PARAMETER id
	Aid id

.PARAMETER name
	Aid name

.PARAMETER scope
	If specified as effective or not specified, all export fields are shown.  If specified as user, only fields with non-default values are shown.
	Valid inputs: effective,user

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/aliases/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.aliases
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsAliasV2

function Get-isiNfsCheckV2{
<#
.SYNOPSIS
	Get Nfs Check

.DESCRIPTION
	Retrieve NFS export validation information.

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/check" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.checks
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsCheckV2

function Get-isiNfsExportsV2{
<#
.SYNOPSIS
	Get Nfs Exports

.DESCRIPTION
	List all NFS exports.

.PARAMETER check
	Check for conflicts when listing exports.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER scope
	If specified as effective or not specified, all export fields are shown.  If specified as user, only fields with non-default values are shown.
	Valid inputs: effective,user

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$check,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($check){
				$queryArguments += 'check=' + $check
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/exports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.exports,$ISIObject.resume
			}else{
				return $ISIObject.exports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExportsV2

function Get-isiNfsExportsSummaryV2{
<#
.SYNOPSIS
	Get Nfs Exports Summary

.DESCRIPTION
	Retrieve NFS export summary information.

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/exports-summary" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.summary
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExportsSummaryV2

function Get-isiNfsExportV2{
<#
.SYNOPSIS
	Get Nfs Export

.DESCRIPTION
	Retrieve export information.

.PARAMETER id
	 id

.PARAMETER scope
	If specified as effective or not specified, all export fields are shown.  If specified as user, only fields with non-default values are shown.
	Valid inputs: effective,user

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			$parameter1 = $id
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/exports/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.exports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExportV2

function Get-isiNfsNlmLocksV2{
<#
.SYNOPSIS
	Get Nfs Nlm Locks

.DESCRIPTION
	List all NLM locks.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/nlm/locks" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.locks,$ISIObject.resume
			}else{
				return $ISIObject.locks
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmLocksV2

function Get-isiNfsNlmSessionsV2{
<#
.SYNOPSIS
	Get Nfs Nlm Sessions

.DESCRIPTION
	List all NLM sessions.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/nlm/sessions" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.sessions,$ISIObject.resume
			}else{
				return $ISIObject.sessions
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmSessionsV2

function Get-isiNfsNlmWaitersV2{
<#
.SYNOPSIS
	Get Nfs Nlm Waiters

.DESCRIPTION
	List all NLM lock waiters.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/nlm/waiters" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.waiters,$ISIObject.resume
			}else{
				return $ISIObject.waiters
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmWaitersV2

function Get-isiNfsSettingsExportV2{
<#
.SYNOPSIS
	Get Nfs Settings Export

.DESCRIPTION
	Retrieve export information.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/settings/export" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsSettingsExportV2

function Get-isiNfsSettingsGlobalV2{
<#
.SYNOPSIS
	Get Nfs Settings Global

.DESCRIPTION
	Retrieve the NFS configuration.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/2/protocols/nfs/settings/global" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsSettingsGlobalV2

function Get-isiNfsSettingsZoneV2{
<#
.SYNOPSIS
	Get Nfs Settings Zone

.DESCRIPTION
	Retrieve the NFS server settings for this zone.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/2/protocols/nfs/settings/zone" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsSettingsZoneV2


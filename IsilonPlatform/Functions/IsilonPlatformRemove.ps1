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


function Remove-isiAuditTopic{
<#
.SYNOPSIS
	Remove Audit Topic

.DESCRIPTION
	Delete the audit topic.

.PARAMETER id
	Topic id

.PARAMETER name
	Topic name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuditTopic')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/audit/topics/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuditTopic

function Remove-isiAuthGroups{
<#
.SYNOPSIS
	Remove Auth Groups

.DESCRIPTION
	Flush the groups cache.

.PARAMETER cached
	If true, only flush cached objects.

.PARAMETER provider
	Filter groups by provider.

.PARAMETER zone
	Filter groups by zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthGroups')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/groups" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthGroups

function Remove-isiAuthGroup{
<#
.SYNOPSIS
	Remove Auth Group

.DESCRIPTION
	Delete the group.

.PARAMETER id
	Group id

.PARAMETER name
	Group name

.PARAMETER cached
	If true, flush the group from the cache.

.PARAMETER provider
	Filter groups by provider.

.PARAMETER zone
	Filter groups by zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthGroup')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/groups/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthGroup

function Remove-isiAuthGroupMember{
<#
.SYNOPSIS
	Remove Auth Group Member

.DESCRIPTION
	Remove the member from the group.

.PARAMETER group_id
	Group group_id

.PARAMETER group_name
	Group group_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER provider
	Filter group members by provider.

.PARAMETER zone
	Filter group members by zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$group_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$group_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('group_id')){
				$parameter1 = $group_id
			} else {
				$parameter1 = $group_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthGroupMember')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/groups/$parameter1/members/$parameter2" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthGroupMember

function Remove-isiAuthMappingIdentities{
<#
.SYNOPSIS
	Remove Auth Mapping Identities

.DESCRIPTION
	Flush the entire idmap cache.

.PARAMETER filter
	Filter to apply when deleting identity mappings.
	Valid inputs: auto,external

.PARAMETER remove
	Delete mapping instead of flush mapping cache.

.PARAMETER zone
	Optional zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('auto','external')][string]$filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$remove,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($filter){
				$queryArguments += 'filter=' + $filter
			}
			if ($remove){
				$queryArguments += 'remove=' + $remove
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthMappingIdentities')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/mapping/identities" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthMappingIdentities

function Remove-isiAuthMappingIdentities{
<#
.SYNOPSIS
	Remove Auth Mapping Identity

.DESCRIPTION
	Flush the entire idmap cache.

.PARAMETER id
	Source id

.PARAMETER name
	Source name

.PARAMETER 2way
	Delete the bi-directional mapping from source to target and target to source.

.PARAMETER remove
	Delete mapping instead of flush mapping from cache.

.PARAMETER target
	Target identity persona.

.PARAMETER zone
	Optional zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$2way,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$remove,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$target,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($2way){
				$queryArguments += '2way=' + $2way
			}
			if ($remove){
				$queryArguments += 'remove=' + $remove
			}
			if ($target){
				$queryArguments += 'target=' + $target
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthMappingIdentities')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/mapping/identities/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthMappingIdentities

function Remove-isiAuthProviderAds{
<#
.SYNOPSIS
	Remove Auth Provider Ads

.DESCRIPTION
	Delete the ADS provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthProviderAds')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/providers/ads/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthProviderAds

function Remove-isiAuthProviderFile{
<#
.SYNOPSIS
	Remove Auth Provider File

.DESCRIPTION
	Delete the file provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthProviderFile')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/providers/file/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthProviderFile

function Remove-isiAuthProviderKrb5{
<#
.SYNOPSIS
	Remove Auth Provider Krb5

.DESCRIPTION
	Delete the KRB5 provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthProviderKrb5')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/providers/krb5/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthProviderKrb5

function Remove-isiAuthProviderLdap{
<#
.SYNOPSIS
	Remove Auth Provider Ldap

.DESCRIPTION
	Delete the LDAP provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthProviderLdap')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/providers/ldap/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthProviderLdap

function Remove-isiAuthProviderLocal{
<#
.SYNOPSIS
	Remove Auth Provider Local

.DESCRIPTION
	Delete the local provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthProviderLocal')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/providers/local/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthProviderLocal

function Remove-isiAuthProviderNis{
<#
.SYNOPSIS
	Remove Auth Provider Nis

.DESCRIPTION
	Delete the NIS provider.

.PARAMETER id
	Provider id

.PARAMETER name
	Provider name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthProviderNis')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/providers/nis/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthProviderNis

function Remove-isiAuthRole{
<#
.SYNOPSIS
	Remove Auth Role

.DESCRIPTION
	Delete the role.

.PARAMETER id
	Role id

.PARAMETER name
	Role name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthRole')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/roles/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthRole

function Remove-isiAuthRoleMember{
<#
.SYNOPSIS
	Remove Auth Role Member

.DESCRIPTION
	Remove a member from the role.

.PARAMETER role_id
	Role role_id

.PARAMETER role_name
	Role role_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$role_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$role_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
			} else {
				$parameter1 = $role_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthRoleMember')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/roles/$parameter1/members/$parameter2" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthRoleMember

function Remove-isiAuthRolePrivilege{
<#
.SYNOPSIS
	Remove Auth Role Privilege

.DESCRIPTION
	Remove a privilege from a role.

.PARAMETER role_id
	Role role_id

.PARAMETER role_name
	Role role_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$role_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$role_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
			} else {
				$parameter1 = $role_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthRolePrivilege')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/roles/$parameter1/privileges/$parameter2" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthRolePrivilege

function Remove-isiAuthSettingsKrb5Domain{
<#
.SYNOPSIS
	Remove Auth Settings Krb5 Domain

.DESCRIPTION
	Remove a krb5 domain.

.PARAMETER id
	Domain id

.PARAMETER name
	Domain name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthSettingsKrb5Domain')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/settings/krb5/domains/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthSettingsKrb5Domain

function Remove-isiAuthSettingsKrb5Realm{
<#
.SYNOPSIS
	Remove Auth Settings Krb5 Realm

.DESCRIPTION
	Remove a realm.

.PARAMETER id
	Realm id

.PARAMETER name
	Realm name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthSettingsKrb5Realm')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/auth/settings/krb5/realms/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthSettingsKrb5Realm

function Remove-isiAuthUsers{
<#
.SYNOPSIS
	Remove Auth Users

.DESCRIPTION
	Flush the users cache.

.PARAMETER cached
	If true, only flush cached objects.

.PARAMETER provider
	Filter users by provider.

.PARAMETER zone
	Filter users by zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthUsers')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/users" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthUsers

function Remove-isiAuthUser{
<#
.SYNOPSIS
	Remove Auth User

.DESCRIPTION
	Delete the user.

.PARAMETER id
	User id

.PARAMETER name
	User name

.PARAMETER cached
	If true, flush the user from the cache.

.PARAMETER provider
	Filter users by provider.

.PARAMETER zone
	Filter users by zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$cached,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthUser')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/users/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthUser

function Remove-isiAuthUserMemberOfGroup{
<#
.SYNOPSIS
	Remove Auth User Member Of Group

.DESCRIPTION
	Remove the user from the group.

.PARAMETER user_id
	User user_id

.PARAMETER user_name
	User user_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER provider
	Filter groups by provider.

.PARAMETER zone
	Filter groups by zone.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$user_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$user_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
			} else {
				$parameter1 = $user_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiAuthUserMemberOfGroup')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/auth/users/$parameter1/member_of/$parameter2" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiAuthUserMemberOfGroup

function Remove-isiCloudAccount{
<#
.SYNOPSIS
	Remove Cloud Account

.DESCRIPTION
	Delete cloud account.

.PARAMETER id
	Account id

.PARAMETER name
	Account name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiCloudAccount')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/cloud/accounts/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiCloudAccount

function Remove-isiCloudPool{
<#
.SYNOPSIS
	Remove Cloud Pool

.DESCRIPTION
	Delete a cloud pool.

.PARAMETER id
	Pool id

.PARAMETER name
	Pool name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiCloudPool')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/cloud/pools/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiCloudPool

function Remove-isiDebugStats{
<#
.SYNOPSIS
	Remove Debug Stats

.DESCRIPTION
	Clear per-resource statistics counters.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiDebugStats')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/debug/stats" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiDebugStats

function Remove-isiFilepoolPolicy{
<#
.SYNOPSIS
	Remove Filepool Policy

.DESCRIPTION
	Delete file pool policy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiFilepoolPolicy')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/filepool/policies/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiFilepoolPolicy

function Remove-isiFsaResult{
<#
.SYNOPSIS
	Remove Fsa Result

.DESCRIPTION
	Delete the result set.

.PARAMETER id
	Result id

.PARAMETER name
	Result name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiFsaResult')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/fsa/results/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiFsaResult

function Remove-isiFsaSettings{
<#
.SYNOPSIS
	Remove Fsa Settings

.DESCRIPTION
	Revert all settings to their defaults.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiFsaSettings')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/fsa/settings" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiFsaSettings

function Remove-isiJobPolicy{
<#
.SYNOPSIS
	Remove Job Policy

.DESCRIPTION
	Delete a job impact policy.  System policies may not be deleted.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiJobPolicy')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/job/policies/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiJobPolicy

function Remove-isiHdfsProxyUser{
<#
.SYNOPSIS
	Remove Hdfs Proxyuser

.DESCRIPTION
	Delete a a HDFS proxyuser.

.PARAMETER id
	Proxyuser id

.PARAMETER name
	Proxyuser name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiHdfsProxyUser')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiHdfsProxyUser

function Remove-isiHdfsProxyUserMember{
<#
.SYNOPSIS
	Remove Hdfs Proxyuser Member

.DESCRIPTION
	Remove a member from the HDFS proxyuser.

.PARAMETER proxyuser_id
	Proxyuser proxyuser_id

.PARAMETER proxyuser_name
	Proxyuser proxyuser_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$proxyuser_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$proxyuser_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('proxyuser_id')){
				$parameter1 = $proxyuser_id
			} else {
				$parameter1 = $proxyuser_name
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
			} else {
				$parameter2 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiHdfsProxyUserMember')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1/members/$parameter2" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiHdfsProxyUserMember

function Remove-isiHdfsRack{
<#
.SYNOPSIS
	Remove Hdfs Rack

.DESCRIPTION
	Delete the HDFS rack.

.PARAMETER id
	Rack id

.PARAMETER name
	Rack name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiHdfsRack')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/hdfs/racks/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiHdfsRack

function Remove-isiNfsExport{
<#
.SYNOPSIS
	Remove Nfs Export

.DESCRIPTION
	Delete the export.

.PARAMETER id
	 id

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiNfsExport')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/nfs/exports/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiNfsExport

function Remove-isiNfsNlmSession{
<#
.SYNOPSIS
	Remove Nfs Nlm Session

.DESCRIPTION
	Delete an NLM session.

.PARAMETER id
	NLM Session id

.PARAMETER name
	NLM Session name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiNfsNlmSession')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/nfs/nlm/sessions/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiNfsNlmSession

function Remove-isiSmbOpenfile{
<#
.SYNOPSIS
	Remove Smb Openfile

.DESCRIPTION
	Close the file in the SMB server.

.PARAMETER id
	Openfile id

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSmbOpenfile')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/smb/openfiles/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSmbOpenfile

function Remove-isiSmbSessionComputer{
<#
.SYNOPSIS
	Remove Smb Session

.DESCRIPTION
	Close the SMB session.

.PARAMETER id
	Computer id

.PARAMETER computer
	Computer computer

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$computer,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $computer
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSmbSessionComputer')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/smb/sessions/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSmbSessionComputer

function Remove-isiSmbSessionUser{
<#
.SYNOPSIS
	Remove Smb Session User

.DESCRIPTION
	Close the SMB session.

.PARAMETER id
	Computer id

.PARAMETER computer
	Computer computer

.PARAMETER user
	 user

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$computer,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1)][ValidateNotNullOrEmpty()][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $computer
			}
			$parameter2 = $user
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSmbSessionUser')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/smb/sessions/$parameter1/$parameter2" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSmbSessionUser

function Remove-isiSmbShares{
<#
.SYNOPSIS
	Remove Smb Shares

.DESCRIPTION
	Delete multiple smb shares.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSmbShares')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/protocols/smb/shares" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSmbShares

function Remove-isiSmbShare{
<#
.SYNOPSIS
	Remove Smb Share

.DESCRIPTION
	Delete the share.

.PARAMETER id
	Share id

.PARAMETER name
	Share name

.PARAMETER zone
	Zone which contains this share.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSmbShare')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/protocols/smb/shares/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSmbShare

function Remove-isiQuotas{
<#
.SYNOPSIS
	Remove Quotas

.DESCRIPTION
	Delete all or matching quotas.

.PARAMETER enforced
	Only delete quotas with this enforcement (non-accounting).

.PARAMETER include_snapshots
	Only delete quotas with this setting for include_snapshots.

.PARAMETER path
	Only delete quotas matching this path (see also recurse_path_*).

.PARAMETER persona
	Only delete user or group quotas matching this persona (must be used with the corresponding type argument).  Format is <PERSONA_TYPE>:<string/integer>, where PERSONA_TYPE is one of USER, GROUP, SID, ID, or GID.

.PARAMETER recurse_path_children
	If used with the path argument, delete all quotas at that path or any descendent sub-directory.

.PARAMETER recurse_path_parents
	If used with the path argument, delete all quotas at that path or any parent directory.

.PARAMETER type
	Only delete quotas matching this type.
	Valid inputs: directory,user,group,default-user,default-group

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$enforced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$include_snapshots,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$persona,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][bool]$recurse_path_children,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$recurse_path_parents,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('directory','user','group','default-user','default-group')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($enforced){
				$queryArguments += 'enforced=' + $enforced
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
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotas')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/quota/quotas" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotas

function Remove-isiQuota{
<#
.SYNOPSIS
	Remove Quota

.DESCRIPTION
	Delete the quota.

.PARAMETER id
	Quota id

.PARAMETER name
	Quota name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuota')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/quotas/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuota

function Remove-isiQuotaNotifications{
<#
.SYNOPSIS
	Remove Quota Notifications

.DESCRIPTION
	Delete all quota specific rules. The quota will then use the global rules.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('quota_id')){
				$parameter1 = $quota_id
			} else {
				$parameter1 = $quota_name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaNotifications')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/quotas/$parameter1/notifications" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaNotifications

function Remove-isiQuotaNotification{
<#
.SYNOPSIS
	Remove Quota Notification

.DESCRIPTION
	Delete the notification rule.

.PARAMETER quota_id
	Quota quota_id

.PARAMETER quota_name
	Quota quota_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaNotification')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/quotas/$parameter1/notifications/$parameter2" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaNotification

function Remove-isiQuotaReport{
<#
.SYNOPSIS
	Remove Quota Report

.DESCRIPTION
	Delete the report.

.PARAMETER id
	Report id

.PARAMETER name
	Report name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaReport')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/reports/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaReport

function Remove-isiQuotaSettingsMappings{
<#
.SYNOPSIS
	Remove Quota Settings Mappings

.DESCRIPTION
	Delete all rules.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaSettingsMappings')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/settings/mappings" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaSettingsMappings

function Remove-isiQuotaSettingsMapping{
<#
.SYNOPSIS
	Remove Quota Settings Mapping

.DESCRIPTION
	Delete the mapping.

.PARAMETER id
	Quota id

.PARAMETER name
	Quota name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaSettingsMapping')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/settings/mappings/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaSettingsMapping

function Remove-isiQuotaSettingsNotifications{
<#
.SYNOPSIS
	Remove Quota Settings Notifications

.DESCRIPTION
	Delete all rules.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaSettingsNotifications')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/settings/notifications" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaSettingsNotifications

function Remove-isiQuotaSettingsNotification{
<#
.SYNOPSIS
	Remove Quota Settings Notification

.DESCRIPTION
	Delete the notification rule.

.PARAMETER id
	Notification id

.PARAMETER name
	Notification name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiQuotaSettingsNotification')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/quota/settings/notifications/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiQuotaSettingsNotification

function Remove-isiSnapshotAliases{
<#
.SYNOPSIS
	Remove Snapshot Aliases

.DESCRIPTION
	Delete all or matching snapshot aliases.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotAliases')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/aliases" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotAliases

function Remove-isiSnapshotAlias{
<#
.SYNOPSIS
	Remove Snapshot Aliase

.DESCRIPTION
	Delete the snapshot alias

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotAlias')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/aliases/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotAlias

function Remove-isiSnapshotChangelist{
<#
.SYNOPSIS
	Remove Snapshot Changelist

.DESCRIPTION
	Delete the specified changelist.

.PARAMETER id
	Changelist id

.PARAMETER name
	Changelist name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotChangelist')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/changelists/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotChangelist

function Remove-isiSnapshotRepstate{
<#
.SYNOPSIS
	Remove Snapshot Repstate

.DESCRIPTION
	Delete the specified repstate.

.PARAMETER id
	Repstate id

.PARAMETER name
	Repstate name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotRepstate')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/repstates/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotRepstate

function Remove-isiSnapshotSchedule{
<#
.SYNOPSIS
	Remove Snapshot Schedule

.DESCRIPTION
	Delete the schedule. This does not affect already created snapshots.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotSchedule')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/schedules/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotSchedule

function Remove-isiSnapshots{
<#
.SYNOPSIS
	Remove Snapshots

.DESCRIPTION
	Delete all or matching snapshots.

.PARAMETER schedule
	Only list snapshots created by this schedule.

.PARAMETER type
	Only list snapshots matching this type.
	Valid inputs: all,alias,real

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('all','alias','real')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($schedule){
				$queryArguments += 'schedule=' + $schedule
			}
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshots')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/snapshot/snapshots" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshots

function Remove-isiSnapshot{
<#
.SYNOPSIS
	Remove Snapshot

.DESCRIPTION
	Delete the snapshot. Deleted snapshots will be placed into a deleting state until the system can reclaim the space used by the snapshot.

.PARAMETER id
	Snapshot id

.PARAMETER name
	Snapshot name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshot')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/snapshots/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshot

function Remove-isiSnapshotLocks{
<#
.SYNOPSIS
	Remove Snapshot Locks

.DESCRIPTION
	Delete all locks. Will try to drain count of recursively held locks so that the snapshot can be deleted.

.PARAMETER snapshot_id
	Snapshot snapshot_id

.PARAMETER snapshot_name
	Snapshot snapshot_name

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotLocks')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/snapshots/$parameter1/locks" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotLocks

function Remove-isiSnapshotLock{
<#
.SYNOPSIS
	Remove Snapshot Lock

.DESCRIPTION
	Delete the snapshot lock.

.PARAMETER snapshot_id
	Snapshot snapshot_id

.PARAMETER snapshot_name
	Snapshot snapshot_name

.PARAMETER id
	 id

.PARAMETER name
	 name

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSnapshotLock')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/snapshot/snapshots/$parameter1/locks/$parameter2" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSnapshotLock

function Remove-isiStoragepoolCompatibilitiesClassActiveId{
<#
.SYNOPSIS
	Remove Storagepool Compatibilities Class Active ID

.DESCRIPTION
	Delete an active compatibility by id

.PARAMETER id
	Active Class id

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiStoragepoolCompatibilitiesClassActiveId')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/storagepool/compatibilities/class/active/<ID>" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiStoragepoolCompatibilitiesClassActiveId

function Remove-isiStoragepoolCompatibilitiesSSDActiveId{
<#
.SYNOPSIS
	Remove Storagepool Compatibilities SSD Active ID

.DESCRIPTION
	Delete an active ssd compatibility by id

.PARAMETER id
	Active SSD id

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiStoragepoolCompatibilitiesSSDActiveId')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/storagepool/compatibilities/ssd/active/<ID>" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiStoragepoolCompatibilitiesSSDActiveId

function Remove-isiStoragepoolNodepool{
<#
.SYNOPSIS
	Remove Storagepool Nodepool

.DESCRIPTION
	Delete node pool.

.PARAMETER id
	Nodepool id

.PARAMETER name
	Nodepool name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiStoragepoolNodepool')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/storagepool/nodepools/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiStoragepoolNodepool

function Remove-isiStoragepoolTiers{
<#
.SYNOPSIS
	Remove Storagepool Tiers

.DESCRIPTION
	Delete all tiers.

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiStoragepoolTiers')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/storagepool/tiers" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiStoragepoolTiers

function Remove-isiStoragepoolTier{
<#
.SYNOPSIS
	Remove Storagepool Tier

.DESCRIPTION
	Delete tier.

.PARAMETER id
	Tier id

.PARAMETER name
	Tier name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiStoragepoolTier')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/storagepool/tiers/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiStoragepoolTier

function Remove-isiSyncPolicies{
<#
.SYNOPSIS
	Remove Sync Policies

.DESCRIPTION
	Delete all SyncIQ policies.

.PARAMETER force
	Ignore any running jobs when preparing to delete a policy.

.PARAMETER local_only
	Skip deleting the policy association on the target.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$local_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
			}
			if ($local_only){
				$queryArguments += 'local_only=' + $local_only
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSyncPolicies')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/sync/policies" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSyncPolicies

function Remove-isiSyncPolicy{
<#
.SYNOPSIS
	Remove Sync Policy

.DESCRIPTION
	Delete a single SyncIQ policy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER force
	Ignore any running jobs when preparing to delete a policy.

.PARAMETER local_only
	Skip deleting the policy association on the target.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$local_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
			}
			if ($local_only){
				$queryArguments += 'local_only=' + $local_only
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSyncPolicy')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/sync/policies/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSyncPolicy

function Remove-isiSyncRules{
<#
.SYNOPSIS
	Remove Sync Rules

.DESCRIPTION
	Delete all SyncIQ performance rules or all rules of a specified type.

.PARAMETER type
	Delete all rules of the specified rule type only.
	Valid inputs: bandwidth,file_count,cpu

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('bandwidth','file_count','cpu')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSyncRules')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/sync/rules" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSyncRules

function Remove-isiSyncRule{
<#
.SYNOPSIS
	Remove Sync Rule

.DESCRIPTION
	Delete a single SyncIQ performance rule.

.PARAMETER id
	Rule id

.PARAMETER name
	Rule name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSyncRule')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/sync/rules/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSyncRule

function Remove-isiSyncTargetPolicy{
<#
.SYNOPSIS
	Remove Sync Target Policy

.DESCRIPTION
	Break the target association with this cluster for this policy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

.PARAMETER force
	Ignore any running jobs when preparing to delete the policy target association.

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiSyncTargetPolicy')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/1/sync/target/policies/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiSyncTargetPolicy

function Remove-isiZone{
<#
.SYNOPSIS
	Remove Zone

.DESCRIPTION
	Delete the access zone.

.PARAMETER id
	Zone id

.PARAMETER name
	Zone name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiZone')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/1/zones/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiZone

function Remove-isiNfsAliasV2{
<#
.SYNOPSIS
	Remove Nfs Aliase

.DESCRIPTION
	Delete the export.

.PARAMETER id
	Aid id

.PARAMETER name
	Aid name

.PARAMETER zone
	Access zone

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiNfsAliasV2')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/2/protocols/nfs/aliases/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiNfsAliasV2

function Remove-isiNfsExportV2{
<#
.SYNOPSIS
	Remove Nfs Export

.DESCRIPTION
	Delete the export.

.PARAMETER id
	 id

.PARAMETER zone
	Access zone

.PARAMETER Force
	Force deletion of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][int]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($zone){
				$queryArguments += 'zone=' + $zone
			}
			$parameter1 = $id
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiNfsExportV2')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource ("/platform/2/protocols/nfs/exports/$parameter1" + "$queryArguments") -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiNfsExportV2

function Remove-isiNfsNlmSessionV2{
<#
.SYNOPSIS
	Remove Nfs Nlm Session

.DESCRIPTION
	Delete an NLM session.

.PARAMETER id
	NLM Session id

.PARAMETER name
	NLM Session name

.PARAMETER Force
	Force deletion of object without prompt

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Remove-isiNfsNlmSessionV2')){
				$ISIObject = Send-isiAPI -Method DELETE -Resource "/platform/2/protocols/nfs/nlm/sessions/$parameter1" -Cluster $Cluster
			}
	}
	End{
	}
}

Export-ModuleMember -Function Remove-isiNfsNlmSessionV2


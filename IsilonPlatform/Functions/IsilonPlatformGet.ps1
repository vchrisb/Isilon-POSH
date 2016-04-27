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


function Get-isiAntivirusPolicies{
<#
.SYNOPSIS
	Get Antivirus Policies

.DESCRIPTION
	List antivirus scan policies.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/antivirus/policies" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.policies,$ISIObject.resume
			}else{
				return $ISIObject.policies
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusPolicies

function Get-isiAntivirusPolicy{
<#
.SYNOPSIS
	Get Antivirus Policy

.DESCRIPTION
	Retrieve one antivirus scan policy.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/antivirus/policies/$parameter1" -Cluster $Cluster
			return $ISIObject.policies
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusPolicy

function Get-isiAntivirusQuarantine{
<#
.SYNOPSIS
	Get Antivirus Quarantine

.DESCRIPTION
	Retrieve the quarantine status of the file at the specified path.

.PARAMETER id
	Path id

.PARAMETER name
	Path name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/antivirus/quarantine/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusQuarantine

function Get-isiAntivirusReportsScans{
<#
.SYNOPSIS
	Get Antivirus Reports Scans

.DESCRIPTION
	List antivirus scan reports.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER policy_id
	If present, only reports for scans associated with this policy will be returned.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER status
	If present, only scan reports with this status will be returned.
	Valid inputs: Finish,Succeeded,Failed,Cancelled,Started,Paused,Resumed,Pending

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$policy_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][ValidateSet('Finish','Succeeded','Failed','Cancelled','Started','Paused','Resumed','Pending')][string]$status,
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
			if ($policy_id){
				$queryArguments += 'policy_id=' + $policy_id
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($status){
				$queryArguments += 'status=' + $status
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/antivirus/reports/scans" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusReportsScans

function Get-isiAntivirusReportsScan{
<#
.SYNOPSIS
	Get Antivirus Reports Scan

.DESCRIPTION
	Retrieve one antivirus scan report.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/antivirus/reports/scans/$parameter1" -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusReportsScan

function Get-isiAntivirusReportsThreats{
<#
.SYNOPSIS
	Get Antivirus Reports Threats

.DESCRIPTION
	List antivirus threat reports.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER file
	If present, only returns threat reports for the given file.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER remediation
	If present, only returns threat reports with the given remediation.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER scan_id
	If present, only returns threat reports associated with the given scan report.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$remediation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$scan_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($file){
				$queryArguments += 'file=' + $file
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($remediation){
				$queryArguments += 'remediation=' + $remediation
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($scan_id){
				$queryArguments += 'scan_id=' + $scan_id
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/antivirus/reports/threats" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusReportsThreats

function Get-isiAntivirusReportsThreat{
<#
.SYNOPSIS
	Get Antivirus Reports Threat

.DESCRIPTION
	Retrieve one antivirus threat report.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/antivirus/reports/threats/$parameter1" -Cluster $Cluster
			return $ISIObject.reports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusReportsThreat

function Get-isiAntivirusServers{
<#
.SYNOPSIS
	Get Antivirus Servers

.DESCRIPTION
	List antivirus servers.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/antivirus/servers" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.servers,$ISIObject.resume
			}else{
				return $ISIObject.servers
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusServers

function Get-isiAntivirusServer{
<#
.SYNOPSIS
	Get Antivirus Server

.DESCRIPTION
	Retrieve one antivirus server entry.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/antivirus/servers/$parameter1" -Cluster $Cluster
			return $ISIObject.servers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusServer

function Get-isiAntivirusSettings{
<#
.SYNOPSIS
	Get Antivirus Settings

.DESCRIPTION
	Retrieve the Antivirus settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/antivirus/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAntivirusSettings

function Get-isiAuditSettingsGlobalv1{
<#
.SYNOPSIS
	Get Audit Global Settings

.DESCRIPTION
	View Global Audit settings.

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

Export-ModuleMember -Function Get-isiAuditSettingsGlobalv1
Set-Alias Get-isiAuditSettingsGlobal -Value Get-isiAuditSettingsGlobalv1
Export-ModuleMember -Alias Get-isiAuditSettingsGlobal

function Get-isiAuditSettingsv3{
<#
.SYNOPSIS
	Get Audit Settings

.DESCRIPTION
	View per-Access Zone Audit settings.

.PARAMETER access_zone
	Access zone which contains audit settings.

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
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/audit/settings" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuditSettingsv3

function Get-isiAuditSettingsGlobal{
<#
.SYNOPSIS
	Get Audit Settings Global

.DESCRIPTION
	View Global Audit settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/audit/settings/global" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuditSettingsGlobal

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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($numeric){
				$queryArguments += 'numeric=' + $numeric
			}
			if ($path){
				$queryArguments += 'path=' + $path
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$access_zone,
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('group_id')){
				$parameter1 = $group_id
			} else {
				$parameter1 = $group_name
			}
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

function Get-isiAuthLogLevel{
<#
.SYNOPSIS
	Get Auth Log Level

.DESCRIPTION
	Get the current authentications service and netlogon logging level.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/auth/log-level" -Cluster $Cluster
			return $ISIObject.level
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthLogLevel

function Get-isiAuthMappingDump{
<#
.SYNOPSIS
	Get Auth Mapping Dump

.DESCRIPTION
	Retrieve all identity mappings (uid, gid, sid, and on-disk) for the supplied source persona.

.PARAMETER nocreate
	Idmap should attempt to create missing identity mappings.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$nocreate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($nocreate){
				$queryArguments += 'nocreate=' + $nocreate
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/mapping/dump" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.identities
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthMappingDump

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$nocreate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($nocreate){
				$queryArguments += 'nocreate=' + $nocreate
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER kerberos_principal
	The Kerberos principal name, of the form user@realm.

.PARAMETER primary_gid
	The user's primary group ID.

.PARAMETER uid
	The user ID.

.PARAMETER user
	The user name.

.PARAMETER access_zone
	The zone the user belongs to.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][array]$gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$kerberos_principal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$primary_gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($gid){
				$queryArguments += 'gid=' + $gid
			}
			if ($kerberos_principal){
				$queryArguments += 'kerberos_principal=' + $kerberos_principal
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
	The zone to which the user mapping applies.

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
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

function Get-isiAuthProvidersAdsv1{
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

Export-ModuleMember -Function Get-isiAuthProvidersAdsv1
Set-Alias Get-isiAuthProvidersAds -Value Get-isiAuthProvidersAdsv1
Export-ModuleMember -Alias Get-isiAuthProvidersAds

function Get-isiAuthProvidersAdsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/ads" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ads
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersAdsv3

function Get-isiAuthProviderAdsv1{
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

Export-ModuleMember -Function Get-isiAuthProviderAdsv1
Set-Alias Get-isiAuthProviderAds -Value Get-isiAuthProviderAdsv1
Export-ModuleMember -Alias Get-isiAuthProviderAds

function Get-isiAuthProviderAdsv3{
<#
.SYNOPSIS
	Get Auth Provider Ads

.DESCRIPTION
	Retrieve the ADS provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/ads/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ads
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsv3

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

function Get-isiAuthProviderAdsDomainsv1{
<#
.SYNOPSIS
	Get Auth Provider Ads Domains

.DESCRIPTION
	List all ADS domains.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

Export-ModuleMember -Function Get-isiAuthProviderAdsDomainsv1
Set-Alias Get-isiAuthProviderAdsDomains -Value Get-isiAuthProviderAdsDomainsv1
Export-ModuleMember -Alias Get-isiAuthProviderAdsDomains

function Get-isiAuthProviderAdsDomainsv3{
<#
.SYNOPSIS
	Get Auth Provider Ads Domains

.DESCRIPTION
	List all ADS domains.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/ads/$parameter1/domains" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.domains
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsDomainsv3

function Get-isiAuthProviderAdsDomainv1{
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

Export-ModuleMember -Function Get-isiAuthProviderAdsDomainv1
Set-Alias Get-isiAuthProviderAdsDomain -Value Get-isiAuthProviderAdsDomainv1
Export-ModuleMember -Alias Get-isiAuthProviderAdsDomain

function Get-isiAuthProviderAdsDomainv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/auth/providers/ads/$parameter1/domains/$parameter2" -Cluster $Cluster
			return $ISIObject.domains
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderAdsDomainv3

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

function Get-isiAuthProvidersKrb5v1{
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

Export-ModuleMember -Function Get-isiAuthProvidersKrb5v1
Set-Alias Get-isiAuthProvidersKrb5 -Value Get-isiAuthProvidersKrb5v1
Export-ModuleMember -Alias Get-isiAuthProvidersKrb5

function Get-isiAuthProvidersKrb5v3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/krb5" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.krb5
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersKrb5v3

function Get-isiAuthProviderKrb5v1{
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

Export-ModuleMember -Function Get-isiAuthProviderKrb5v1
Set-Alias Get-isiAuthProviderKrb5 -Value Get-isiAuthProviderKrb5v1
Export-ModuleMember -Alias Get-isiAuthProviderKrb5

function Get-isiAuthProviderKrb5v3{
<#
.SYNOPSIS
	Get Auth Provider Krb5

.DESCRIPTION
	Retrieve the KRB5 provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/krb5/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.krb5
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderKrb5v3

function Get-isiAuthProvidersLdapv1{
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

Export-ModuleMember -Function Get-isiAuthProvidersLdapv1
Set-Alias Get-isiAuthProvidersLdap -Value Get-isiAuthProvidersLdapv1
Export-ModuleMember -Alias Get-isiAuthProvidersLdap

function Get-isiAuthProvidersLdapv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/ldap" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ldap
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersLdapv3

function Get-isiAuthProviderLdapv1{
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

Export-ModuleMember -Function Get-isiAuthProviderLdapv1
Set-Alias Get-isiAuthProviderLdap -Value Get-isiAuthProviderLdapv1
Export-ModuleMember -Alias Get-isiAuthProviderLdap

function Get-isiAuthProviderLdapv3{
<#
.SYNOPSIS
	Get Auth Provider Ldap

.DESCRIPTION
	Retrieve the LDAP provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/ldap/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.ldap
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderLdapv3

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

function Get-isiAuthProvidersNisv1{
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

Export-ModuleMember -Function Get-isiAuthProvidersNisv1
Set-Alias Get-isiAuthProvidersNis -Value Get-isiAuthProvidersNisv1
Export-ModuleMember -Alias Get-isiAuthProvidersNis

function Get-isiAuthProvidersNisv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/nis" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.nis
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersNisv3

function Get-isiAuthProviderNisv1{
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

Export-ModuleMember -Function Get-isiAuthProviderNisv1
Set-Alias Get-isiAuthProviderNis -Value Get-isiAuthProviderNisv1
Export-ModuleMember -Alias Get-isiAuthProviderNis

function Get-isiAuthProviderNisv3{
<#
.SYNOPSIS
	Get Auth Provider Nis

.DESCRIPTION
	Retrieve the NIS provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/providers/nis/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.nis
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProviderNisv3

function Get-isiAuthProvidersSummaryv1{
<#
.SYNOPSIS
	Get Auth Providers Summary

.DESCRIPTION
	Retrieve the summary information.

.PARAMETER access_zone
	Filter providers by zone.

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
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/auth/providers/summary" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.provider_instances
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersSummaryv1
Set-Alias Get-isiAuthProvidersSummary -Value Get-isiAuthProvidersSummaryv1
Export-ModuleMember -Alias Get-isiAuthProvidersSummary

function Get-isiAuthProvidersSummaryv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/auth/providers/summary" -Cluster $Cluster
			return $ISIObject.provider_instances
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthProvidersSummaryv3

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
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
			if ($psBoundParameters.ContainsKey('role_id')){
				$parameter1 = $role_id
			} else {
				$parameter1 = $role_name
			}
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
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

function Get-isiAuthSettingsAcls{
<#
.SYNOPSIS
	Get Auth Settings Acls

.DESCRIPTION
	Retrieve the ACL policy settings and preset configurations.

.PARAMETER preset
	If specified the preset configuration values for all applicable ACL policies are returned.
	Valid inputs: balanced,unix,windows

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('balanced','unix','windows')][string]$preset,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($preset){
				$queryArguments += 'preset=' + $preset
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/settings/acls" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.acl_policy_settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthSettingsAcls

function Get-isiAuthSettingsGlobal{
<#
.SYNOPSIS
	Get Auth Settings Global

.DESCRIPTION
	Retrieve the global settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER access_zone
	Zone which contains any per-zone settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
	Access zone which contains mapping settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$access_zone,
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

function Get-isiAuthUserMemberOfGroupsv3{
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
			} else {
				$parameter1 = $user_name
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/auth/users/$parameter1/member-of" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.member_of
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiAuthUserMemberOfGroupsv3

function Get-isiAuthUserMemberOfGroupsv1{
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('user_id')){
				$parameter1 = $user_id
			} else {
				$parameter1 = $user_name
			}
			$queryArguments = @()
			if ($provider){
				$queryArguments += 'provider=' + $provider
			}
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiAuthUserMemberOfGroupsv1

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
			$parameter1 = $id
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
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

function Get-isiCloudAccess{
<#
.SYNOPSIS
	Get Cloud Access

.DESCRIPTION
	List all accessible cluster identifiers.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/access" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.clusters
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudAccess

function Get-isiCloudAccess{
<#
.SYNOPSIS
	Get Cloud Access

.DESCRIPTION
	Retrieve cloud access information.

.PARAMETER id
	Guid id

.PARAMETER name
	Guid name

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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/access/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.clusters
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudAccess

function Get-isiCloudAccountsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/accounts" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.accounts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudAccountsv3

function Get-isiCloudAccountv3{
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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/accounts/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.accounts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudAccountv3

function Get-isiCloudJobsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/jobs" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudJobsv3

function Get-isiCloudJobsFilev3{
<#
.SYNOPSIS
	Get Cloud Jobs File

.DESCRIPTION
	Retrieve files associated with a cloudpool job.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

.PARAMETER batch
	If true, only "limit" and "page" arguments are honored.  Query will return all results, unsorted, as quickly as possible.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER page
	Works only when "batch" parameter and "limit" parameters are specified.  Indicates which the page index of results to be returned

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$batch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$page,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
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
			if ($page){
				$queryArguments += 'page=' + $page
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/jobs-files/$parameter1" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.files,$ISIObject.resume
			}else{
				return $ISIObject.files
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudJobsFilev3

function Get-isiCloudJobv3{
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/jobs/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudJobv3

function Get-isiCloudPoolsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/pools" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.pools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudPoolsv3

function Get-isiCloudPoolv3{
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
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cloud/pools/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.pools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudPoolv3

function Get-isiCloudSettingsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cloud/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudSettingsv3

function Get-isiCloudSettingsReportingEula{
<#
.SYNOPSIS
	Get Cloud Settings Reporting Eula

.DESCRIPTION
	View telemetry collection EULA acceptance and content URI.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cloud/settings/reporting-eula" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiCloudSettingsReportingEula

function Get-isiClusterConfigv1{
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

Export-ModuleMember -Function Get-isiClusterConfigv1
Set-Alias Get-isiClusterConfig -Value Get-isiClusterConfigv1
Export-ModuleMember -Alias Get-isiClusterConfig

function Get-isiClusterConfigv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/config" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterConfigv3

function Get-isiClusterEmail{
<#
.SYNOPSIS
	Get Cluster Email

.DESCRIPTION
	Get the cluster email notification settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/email" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterEmail

function Get-isiClusterExternalIPsv1{
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

Export-ModuleMember -Function Get-isiClusterExternalIPsv1

function Get-isiClusterExternalIPsv2{
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

Export-ModuleMember -Function Get-isiClusterExternalIPsv2
Set-Alias Get-isiClusterExternalIPs -Value Get-isiClusterExternalIPsv2
Export-ModuleMember -Alias Get-isiClusterExternalIPs

function Get-isiClusterIdentityv1{
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

Export-ModuleMember -Function Get-isiClusterIdentityv1
Set-Alias Get-isiClusterIdentity -Value Get-isiClusterIdentityv1
Export-ModuleMember -Alias Get-isiClusterIdentity

function Get-isiClusterIdentityv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/identity" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterIdentityv3

function Get-isiClusterNodes{
<#
.SYNOPSIS
	Get Cluster Nodes

.DESCRIPTION
	List the nodes on this cluster.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodes

function Get-isiClusterNodesAvailable{
<#
.SYNOPSIS
	Get Cluster Nodes Available

.DESCRIPTION
	List all nodes that are available to add to this cluster.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes-available" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodesAvailable

function Get-isiClusterNode{
<#
.SYNOPSIS
	Get Cluster Node

.DESCRIPTION
	Retrieve node information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNode

function Get-isiClusterNodeDrives{
<#
.SYNOPSIS
	Get Cluster Node Drives

.DESCRIPTION
	List the drives on this node.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/drives" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeDrives

function Get-isiClusterNodeDrivesPurposelist{
<#
.SYNOPSIS
	Get Cluster Node Drives Purposelist

.DESCRIPTION
	Lists the available purposes for drives in this node.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/drives-purposelist" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeDrivesPurposelist

function Get-isiClusterNodeDrive{
<#
.SYNOPSIS
	Get Cluster Node Drive

.DESCRIPTION
	Retrieve drive information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
			} else {
				$parameter2 = $driveidname2
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeDrive

function Get-isiClusterNodeDriveFirmware{
<#
.SYNOPSIS
	Get Cluster Node Drive Firmware

.DESCRIPTION
	Retrieve drive firmware information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
			} else {
				$parameter2 = $driveidname2
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeDriveFirmware

function Get-isiClusterNodeDriveFirmwareUpdate{
<#
.SYNOPSIS
	Get Cluster Node Drive Firmware Update

.DESCRIPTION
	Retrieve firmware update information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('driveidid2')){
				$parameter2 = $driveidid2
			} else {
				$parameter2 = $driveidname2
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/drives/$parameter2" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeDriveFirmwareUpdate

function Get-isiClusterNodeHardware{
<#
.SYNOPSIS
	Get Cluster Node Hardware

.DESCRIPTION
	Retrieve node hardware identity information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/hardware" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeHardware

function Get-isiClusterNodePartitions{
<#
.SYNOPSIS
	Get Cluster Node Partitions

.DESCRIPTION
	Retrieve node partition information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/partitions" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodePartitions

function Get-isiClusterNodeSensors{
<#
.SYNOPSIS
	Get Cluster Node Sensors

.DESCRIPTION
	Retrieve node sensor information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/sensors" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeSensors

function Get-isiClusterNodeState{
<#
.SYNOPSIS
	Get Cluster Node State

.DESCRIPTION
	Retrieve node state information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/state" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeState

function Get-isiClusterNodeStateReadonly{
<#
.SYNOPSIS
	Get Cluster Node State Readonly

.DESCRIPTION
	Retrieve node readonly state information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/state/readonly" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeStateReadonly

function Get-isiClusterNodeStateServicelight{
<#
.SYNOPSIS
	Get Cluster Node State Servicelight

.DESCRIPTION
	Retrieve node service light state information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/state/servicelight" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeStateServicelight

function Get-isiClusterNodeStateSmartfail{
<#
.SYNOPSIS
	Get Cluster Node State Smartfail

.DESCRIPTION
	Retrieve node smartfail state information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/state/smartfail" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeStateSmartfail

function Get-isiClusterNodeStatus{
<#
.SYNOPSIS
	Get Cluster Node Status

.DESCRIPTION
	Retrieve node status information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/status" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeStatus

function Get-isiClusterNodeStatusBatterystatus{
<#
.SYNOPSIS
	Get Cluster Node Status Batterystatus

.DESCRIPTION
	Retrieve node battery status information.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/nodes/$parameter1/status/batterystatus" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterNodeStatusBatterystatus

function Get-isiClusterOwner{
<#
.SYNOPSIS
	Get Cluster Owner

.DESCRIPTION
	Get the cluster contact info settings

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/1/cluster/owner" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterOwner

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

function Get-isiClusterTimev1{
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

Export-ModuleMember -Function Get-isiClusterTimev1
Set-Alias Get-isiClusterTime -Value Get-isiClusterTimev1
Export-ModuleMember -Alias Get-isiClusterTime

function Get-isiClusterTimev3{
<#
.SYNOPSIS
	Get Cluster Time

.DESCRIPTION
	Retrieve the current time as reported by each node.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/time" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterTimev3

function Get-isiClusterTimezone{
<#
.SYNOPSIS
	Get Cluster Timezone

.DESCRIPTION
	Get the cluster timezone.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/timezone" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterTimezone

function Get-isiClusterTimezoneRegion{
<#
.SYNOPSIS
	Get Cluster Timezone Region

.DESCRIPTION
	List timezone regions.

.PARAMETER id
	Region id

.PARAMETER name
	Region name

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER dst_reset
	This query arg is not needed in normal use cases.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER show_all
	Show all timezones within the region specified in the URI.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$dst_reset,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$show_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($dst_reset){
				$queryArguments += 'dst_reset=' + $dst_reset
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/cluster/timezone/regions/$parameter1" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.regions,$ISIObject.resume
			}else{
				return $ISIObject.regions
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterTimezoneRegion

function Get-isiClusterTimezoneSettings{
<#
.SYNOPSIS
	Get Cluster Timezone Settings

.DESCRIPTION
	Retrieve the cluster timezone.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/timezone/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterTimezoneSettings

function Get-isiClusterVersion{
<#
.SYNOPSIS
	Get Cluster Version

.DESCRIPTION
	Retrieve the OneFS version as reported by each node.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/cluster/version" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiClusterVersion

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
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

function Get-isiEventAlertConditions{
<#
.SYNOPSIS
	Get Event Alert Conditions

.DESCRIPTION
	List all alert conditions.

.PARAMETER channel_ids
	Return only conditions for the specified channel:

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$channel_ids,
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
			if ($channel_ids){
				$queryArguments += 'channel_ids=' + $channel_ids
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
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/event/alert-conditions" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.'alert-conditions',$ISIObject.resume
			}else{
				return $ISIObject.'alert-conditions'
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventAlertConditions

function Get-isiEventAlertCondition{
<#
.SYNOPSIS
	Get Event Alert Condition

.DESCRIPTION
	Retrieve the alert-condition.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/alert-conditions/$parameter1" -Cluster $Cluster
			return $ISIObject.'alert-conditions'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventAlertCondition

function Get-isiEventCategories{
<#
.SYNOPSIS
	Get Event Categories

.DESCRIPTION
	List all eventgroup categories.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/event/categories" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.categories,$ISIObject.resume
			}else{
				return $ISIObject.categories
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventCategories

function Get-isiEventCategory{
<#
.SYNOPSIS
	Get Event Category

.DESCRIPTION
	Retrieve the eventgroup category.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/categories/$parameter1" -Cluster $Cluster
			return $ISIObject.categories
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventCategory

function Get-isiEventChannels{
<#
.SYNOPSIS
	Get Event Channels

.DESCRIPTION
	List all channels.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/event/channels" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.channels,$ISIObject.resume
			}else{
				return $ISIObject.channels
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventChannels

function Get-isiEventChannel{
<#
.SYNOPSIS
	Get Event Channel

.DESCRIPTION
	Retrieve the alert-condition.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/channels/$parameter1" -Cluster $Cluster
			return $ISIObject.'alert-conditions'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventChannel

function Get-isiEventEventgroupDefinitions{
<#
.SYNOPSIS
	Get Event Eventgroup Definitions

.DESCRIPTION
	List all eventgroup definitions.

.PARAMETER category
	Return eventgroups in the specified category

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$category,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($category){
				$queryArguments += 'category=' + $category
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/event/eventgroup-definitions" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.'eventgroup-definitions',$ISIObject.resume
			}else{
				return $ISIObject.'eventgroup-definitions'
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventEventgroupDefinitions

function Get-isiEventEventgroupDefinition{
<#
.SYNOPSIS
	Get Event Eventgroup Definition

.DESCRIPTION
	Retrieve the eventgroup definition.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/eventgroup-definitions/$parameter1" -Cluster $Cluster
			return $ISIObject.'eventgroup-definitions'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventEventgroupDefinition

function Get-isiEventEventgroupOccurrences{
<#
.SYNOPSIS
	Get Event Eventgroup Occurrences

.DESCRIPTION
	List all eventgroup occurrences.

.PARAMETER begin
	events that are in progress after this time

.PARAMETER cause
	Filter for cause

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER end
	events that were in progress before this time

.PARAMETER event_count
	events for which event_count > this

.PARAMETER fixer
	Filter for eventgroup fixer

.PARAMETER ignore
	Filter for ignored eventgroups

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resolved
	Filter for resolved eventgroups

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$begin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$cause,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$end,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$event_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$fixer,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][bool]$ignore,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][bool]$resolved,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($begin){
				$queryArguments += 'begin=' + $begin
			}
			if ($cause){
				$queryArguments += 'cause=' + $cause
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($end){
				$queryArguments += 'end=' + $end
			}
			if ($event_count){
				$queryArguments += 'event_count=' + $event_count
			}
			if ($fixer){
				$queryArguments += 'fixer=' + $fixer
			}
			if ($ignore){
				$queryArguments += 'ignore=' + $ignore
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($resolved){
				$queryArguments += 'resolved=' + $resolved
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/event/eventgroup-occurrences" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.'eventgroup-occurrences',$ISIObject.resume
			}else{
				return $ISIObject.'eventgroup-occurrences'
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventEventgroupOccurrences

function Get-isiEventEventgroupOccurrence{
<#
.SYNOPSIS
	Get Event Eventgroup Occurrence

.DESCRIPTION
	Retrieve individual eventgroup occurrence.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/eventgroup-occurrences/$parameter1" -Cluster $Cluster
			return $ISIObject.'eventgroup-occurrences'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventEventgroupOccurrence

function Get-isiEventEventlists{
<#
.SYNOPSIS
	Get Event Eventlists

.DESCRIPTION
	List all event occurrences grouped by eventgroup occurrence.

.PARAMETER event_instance
	Return only this event occurrence

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$event_instance,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($event_instance){
				$queryArguments += 'event_instance=' + $event_instance
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/event/eventlists" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.eventlists,$ISIObject.resume
			}else{
				return $ISIObject.eventlists
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventEventlists

function Get-isiEventEventlist{
<#
.SYNOPSIS
	Get Event Eventlist

.DESCRIPTION
	Retrieve the list of events for a eventgroup occureence.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/eventlists/$parameter1" -Cluster $Cluster
			return $ISIObject.eventlist
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventEventlist

function Get-isiEventSettings{
<#
.SYNOPSIS
	Get Event Settings

.DESCRIPTION
	Retrieve the settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/event/settings" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiEventSettings

function Get-isiFileFilterSettings{
<#
.SYNOPSIS
	Get File Filter Settings

.DESCRIPTION
	View File Filtering settings of an access zone

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/file-filter/settings" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFileFilterSettings

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
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
			return $ISIObject.settings
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

function Get-isiFsaResultsv1{
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

Export-ModuleMember -Function Get-isiFsaResultsv1
Set-Alias Get-isiFsaResults -Value Get-isiFsaResultsv1
Export-ModuleMember -Alias Get-isiFsaResults

function Get-isiFsaResultsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/fsa/results" -Cluster $Cluster
			return $ISIObject.results
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultsv3

function Get-isiFsaResultv1{
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

Export-ModuleMember -Function Get-isiFsaResultv1
Set-Alias Get-isiFsaResult -Value Get-isiFsaResultv1
Export-ModuleMember -Alias Get-isiFsaResult

function Get-isiFsaResultv3{
<#
.SYNOPSIS
	Get Fsa Result

.DESCRIPTION
	Retrieve result set information.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/fsa/results/$parameter1" -Cluster $Cluster
			return $ISIObject.results
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultv3

function Get-isiFsaResultDirectories{
<#
.SYNOPSIS
	Get Fsa Result Directories

.DESCRIPTION
	This resource retrieves directory information. ID in the resource path is the result set ID.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER comp_report
	Result set identifier for comparison of database results.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Limit the number of reported subdirectories.

.PARAMETER path
	Primary directory path to report usage information, which may be specified instead of a LIN.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$comp_report,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($comp_report){
				$queryArguments += 'comp_report=' + $comp_report
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($path){
				$queryArguments += 'path=' + $path
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/fsa/results/$parameter1/directories" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultDirectories

function Get-isiFsaResultDirectory{
<#
.SYNOPSIS
	Get Fsa Result Directory

.DESCRIPTION
	This resource retrieves directory information. ID in the resource path is the result set ID.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER linid2
	 linid2

.PARAMETER linname2
	 linname2

.PARAMETER comp_report
	Result set identifier for comparison of database results.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Limit the number of reported subdirectories.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$linid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$linname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$comp_report,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('linid2')){
				$parameter2 = $linid2
			} else {
				$parameter2 = $linname2
			}
			$queryArguments = @()
			if ($comp_report){
				$queryArguments += 'comp_report=' + $comp_report
			}
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/fsa/results/$parameter1/directories/$parameter2" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultDirectory

function Get-isiFsaResultHistogram{
<#
.SYNOPSIS
	Get Fsa Result Histogram

.DESCRIPTION
	This resource retrieves a histogram of file counts for an individual FSA result set. ID in the resource path is the result set ID.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/fsa/results/$parameter1/histogram" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultHistogram

function Get-isiFsaResultHistogram{
<#
.SYNOPSIS
	Get Fsa Result Histogram

.DESCRIPTION
	This resource retrieves a histogram of file counts for an individual FSA result set. ID in the resource path is the result set ID.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER statid2
	 statid2

.PARAMETER statname2
	 statname2

.PARAMETER atime_filter
	Filter according to file accessed time, where the filter value specifies a negative number of seconds representing a time before the begin time of the report. The list of valid atime filter values may be found by performing a histogram breakout by atime and viewing the resulting key values.

.PARAMETER attribute_filter
	Filter according to the name of a file user attribute.

.PARAMETER comp_report
	Result set identifier for comparison of database results.

.PARAMETER ctime_filter
	Filter according to file modified time, where the filter value specifies a negative number of seconds representing a time before the begin time of the report. The list of valid ctime filter values may be found by performing a histogram breakout by ctime and viewing the resulting key values.

.PARAMETER directory_filter
	Filter according to a specific directory, which includes all of its subdirectories.

.PARAMETER disk_pool_filter
	Filter according to the name of a disk pool, which is a set of drives that represent an independent failure domain.

.PARAMETER log_size_filter
	Filter according to file logical size, where the filter value specifies the lower bound in bytes to a set of files that have been grouped by logical size. The list of valid log_size filter values may be found by performing a histogram breakout by log_size and viewing the resulting key values.

.PARAMETER node_pool_filter
	Filter according to the name of a node pool, which is a set of disk pools that belong to nodes of the same equivalence class.

.PARAMETER path_ext_filter
	Filter according to the name of a single file extension.

.PARAMETER phys_size_filter
	Filter according to file physical size, where the filter value specifies the lower bound in bytes to a set of files that have been grouped by physical size. The list of valid phys_size filter values may be found by performing a histogram breakout by phys_size and viewing the resulting key values.

.PARAMETER tier_filter
	Filter according to the name of a storage tier, which is a user-created set of node pools.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$statid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$statname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$atime_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$attribute_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$comp_report,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][int]$ctime_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$directory_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$disk_pool_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][int]$log_size_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$node_pool_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$path_ext_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][int]$phys_size_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$tier_filter,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('statid2')){
				$parameter2 = $statid2
			} else {
				$parameter2 = $statname2
			}
			$queryArguments = @()
			if ($atime_filter){
				$queryArguments += 'atime_filter=' + $atime_filter
			}
			if ($attribute_filter){
				$queryArguments += 'attribute_filter=' + $attribute_filter
			}
			if ($comp_report){
				$queryArguments += 'comp_report=' + $comp_report
			}
			if ($ctime_filter){
				$queryArguments += 'ctime_filter=' + $ctime_filter
			}
			if ($directory_filter){
				$queryArguments += 'directory_filter=' + $directory_filter
			}
			if ($disk_pool_filter){
				$queryArguments += 'disk_pool_filter=' + $disk_pool_filter
			}
			if ($log_size_filter){
				$queryArguments += 'log_size_filter=' + $log_size_filter
			}
			if ($node_pool_filter){
				$queryArguments += 'node_pool_filter=' + $node_pool_filter
			}
			if ($path_ext_filter){
				$queryArguments += 'path_ext_filter=' + $path_ext_filter
			}
			if ($phys_size_filter){
				$queryArguments += 'phys_size_filter=' + $phys_size_filter
			}
			if ($tier_filter){
				$queryArguments += 'tier_filter=' + $tier_filter
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/fsa/results/$parameter1/histogram/$parameter2" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultHistogram

function Get-isiFsaResultHistogramBy{
<#
.SYNOPSIS
	Get Fsa Result Histogram By

.DESCRIPTION
	This resource retrieves a histogram breakout for an individual FSA result set. ID in the resource path is the result set ID.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER statid2
	 statid2

.PARAMETER statname2
	 statname2

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$statid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$statname2,
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
			if ($psBoundParameters.ContainsKey('statid2')){
				$parameter2 = $statid2
			} else {
				$parameter2 = $statname2
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/fsa/results/$parameter1/histogram/$parameter2" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultHistogramBy

function Get-isiFsaResultTopDirs{
<#
.SYNOPSIS
	Get Fsa Result Top Dirs

.DESCRIPTION
	This resource retrieves the top directories. ID in the resource path is the result set ID.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/fsa/results/$parameter1/top-dirs" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultTopDirs

function Get-isiFsaResultTopDir{
<#
.SYNOPSIS
	Get Fsa Result Top Dir

.DESCRIPTION
	This resource retrieves the top directories. ID in the resource path is the result set ID.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER statid2
	 statid2

.PARAMETER statname2
	 statname2

.PARAMETER comp_report
	Result set identifier for comparison of database results.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Number of results from start index. Default value of 1000.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER start
	Starting index for results. Default value of 0.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$statid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$statname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$comp_report,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][int]$start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('statid2')){
				$parameter2 = $statid2
			} else {
				$parameter2 = $statname2
			}
			$queryArguments = @()
			if ($comp_report){
				$queryArguments += 'comp_report=' + $comp_report
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($start){
				$queryArguments += 'start=' + $start
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/fsa/results/$parameter1/top-dirs/$parameter2" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultTopDir

function Get-isiFsaResultTopFiles{
<#
.SYNOPSIS
	Get Fsa Result Top Files

.DESCRIPTION
	This resource retrieves the top files. ID in the resource path is the result set ID.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/fsa/results/$parameter1/top-files" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultTopFiles

function Get-isiFsaResultTopFile{
<#
.SYNOPSIS
	Get Fsa Result Top File

.DESCRIPTION
	This resource retrieves the top files. ID in the resource path is the result set ID.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER statid2
	 statid2

.PARAMETER statname2
	 statname2

.PARAMETER comp_report
	Result set identifier for comparison of database results.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Number of results from start index. Default value of 1000.

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER start
	Starting index for results. Default value of 0.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$statid2,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$statname2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$comp_report,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][int]$start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			if ($psBoundParameters.ContainsKey('statid2')){
				$parameter2 = $statid2
			} else {
				$parameter2 = $statname2
			}
			$queryArguments = @()
			if ($comp_report){
				$queryArguments += 'comp_report=' + $comp_report
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($start){
				$queryArguments += 'start=' + $start
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/fsa/results/$parameter1/top-files/$parameter2" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFsaResultTopFile

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

function Get-isiHardeningState{
<#
.SYNOPSIS
	Get Hardening State

.DESCRIPTION
	Get the state of the current hardening operation, if one is happening.  Note that this is different from the /status resource, which returns the overall hardening status of the cluster.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/hardening/state" -Cluster $Cluster
			return $ISIObject.state
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHardeningState

function Get-isiHardeningStatus{
<#
.SYNOPSIS
	Get Hardening Status

.DESCRIPTION
	Get a message indicating whether or not the cluster is hardened. Note that this is different from the /state resource, which returns the state of a specific hardening operation (apply or revert).

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/hardening/status" -Cluster $Cluster
			return $ISIObject.status
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHardeningStatus

function Get-isiHardwareFcports{
<#
.SYNOPSIS
	Get Hardware Fcports

.DESCRIPTION
	Get list of fibre-channel ports

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/hardware/fcports" -Cluster $Cluster
			return $ISIObject.fcports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHardwareFcports

function Get-isiHardwareFcport{
<#
.SYNOPSIS
	Get Hardware Fcport

.DESCRIPTION
	Get one fibre-channel port

.PARAMETER id
	Port id

.PARAMETER name
	Port name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/hardware/fcports/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHardwareFcport

function Get-isiHardwareTapes{
<#
.SYNOPSIS
	Get Hardware Tapes

.DESCRIPTION
	Get list Tape and Changer devices

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/hardware/tapes" -Cluster $Cluster
			return $ISIObject.devices
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHardwareTapes

function Get-isiJobEventsv1{
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][array]$state,
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

Export-ModuleMember -Function Get-isiJobEventsv1
Set-Alias Get-isiJobEvents -Value Get-isiJobEventsv1
Export-ModuleMember -Alias Get-isiJobEvents

function Get-isiJobEventsv3{
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

.PARAMETER key
	Restrict the query to the given key name.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER state
	Restrict the query to events containing the given state.
	Valid inputs: running,paused_user,paused_system,paused_policy,paused_priority,cancelled_user,cancelled_system,failed,succeeded,unknown

.PARAMETER timeout_ms
	Query timeout in milliseconds. The default is 10000 ms.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][ValidateSet('running','paused_user','paused_system','paused_policy','paused_priority','cancelled_user','cancelled_system','failed','succeeded','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][int]$timeout_ms,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($key){
				$queryArguments += 'key=' + $key
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
			if ($timeout_ms){
				$queryArguments += 'timeout_ms=' + $timeout_ms
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/job/events" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.events,$ISIObject.resume
			}else{
				return $ISIObject.events
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobEventsv3

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

function Get-isiJobsv1{
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

Export-ModuleMember -Function Get-isiJobsv1
Set-Alias Get-isiJobs -Value Get-isiJobsv1
Export-ModuleMember -Alias Get-isiJobs

function Get-isiJobsv3{
<#
.SYNOPSIS
	Get Job Jobs

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/job/jobs" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.jobs,$ISIObject.resume
			}else{
				return $ISIObject.jobs
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobsv3

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

function Get-isiJobRecent{
<#
.SYNOPSIS
	Get Job Recent

.DESCRIPTION
	List recently completed jobs.

.PARAMETER limit
	Max number of recent jobs to return. The default is 8, the max is 100.

.PARAMETER timeout_ms
	Query timeout in milliseconds. The default is 10000 ms.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][int]$timeout_ms,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($timeout_ms){
				$queryArguments += 'timeout_ms=' + $timeout_ms
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/job/recent" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.recent
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobRecent

function Get-isiJobReportsv1{
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

Export-ModuleMember -Function Get-isiJobReportsv1
Set-Alias Get-isiJobReports -Value Get-isiJobReportsv1
Export-ModuleMember -Alias Get-isiJobReports

function Get-isiJobReportsv3{
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

.PARAMETER timeout_ms
	Query timeout in milliseconds. The default is 10000 ms.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][int]$timeout_ms,
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
			if ($timeout_ms){
				$queryArguments += 'timeout_ms=' + $timeout_ms
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/job/reports" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.reports,$ISIObject.resume
			}else{
				return $ISIObject.reports
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiJobReportsv3

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

function Get-isiLocalClusterTime{
<#
.SYNOPSIS
	Get Local Cluster Time

.DESCRIPTION
	Get the current time on the local node.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/local/cluster/time" -Cluster $Cluster
			return $ISIObject.time
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiLocalClusterTime

function Get-isiLocalClusterVersion{
<#
.SYNOPSIS
	Get Local Cluster Version

.DESCRIPTION
	This method has no description because it is unsupported.

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
			$ISIObject = Send-isiAPI -Method GET_JSON -Resource "/platform/3/local/cluster/version" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiLocalClusterVersion

function Get-isiNetworkDnscache{
<#
.SYNOPSIS
	Get Network Dnscache

.DESCRIPTION
	View network dns cache settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/network/dnscache" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkDnscache

function Get-isiNetworkExternal{
<#
.SYNOPSIS
	Get Network External

.DESCRIPTION
	View external network settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/network/external" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkExternal

function Get-isiNetworkGroupnets{
<#
.SYNOPSIS
	Get Network Groupnets

.DESCRIPTION
	Get a list of groupnets.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/groupnets" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.groupnets,$ISIObject.resume
			}else{
				return $ISIObject.groupnets
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkGroupnets

function Get-isiNetworkGroupnet{
<#
.SYNOPSIS
	Get Network Groupnet

.DESCRIPTION
	View a network groupnet.

.PARAMETER id
	Groupnet id

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/network/groupnets/$parameter1" -Cluster $Cluster
			return $ISIObject.groupnets
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkGroupnet

function Get-isiNetworkGroupnetSubnets{
<#
.SYNOPSIS
	Get Network Groupnet Subnets

.DESCRIPTION
	Get a list of subnets.

.PARAMETER id
	Groupnet id

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
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/groupnets/$parameter1/subnets" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.subnets,$ISIObject.resume
			}else{
				return $ISIObject.subnets
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkGroupnetSubnets

function Get-isiNetworkGroupnetSubnet{
<#
.SYNOPSIS
	Get Network Groupnet Subnet

.DESCRIPTION
	View a network subnet.

.PARAMETER groupnet_id
	Groupnet groupnet_id

.PARAMETER groupnet_name
	Groupnet groupnet_name

.PARAMETER id
	 id

.PARAMETER enforce
	force modifying this subnet even if it causes an MTU conflict.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$groupnet_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$groupnet_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('groupnet_id')){
				$parameter1 = $groupnet_id
			} else {
				$parameter1 = $groupnet_name
			}
			$parameter2 = $id
			$queryArguments = @()
			if ($enforce){
				$queryArguments += 'force=' + $enforce
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/groupnets/$parameter1/subnets/$parameter2" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.subnets
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkGroupnetSubnet

function Get-isiNetworkGroupnetSubnetPools{
<#
.SYNOPSIS
	Get Network Groupnet Subnet Pools

.DESCRIPTION
	Get a list of network pools.

.PARAMETER groupnet_id
	Groupnet groupnet_id

.PARAMETER groupnet_name
	Groupnet groupnet_name

.PARAMETER id
	 id

.PARAMETER access_zone
	If specified, only pools with this zone name will be returned.

.PARAMETER alloc_method
	If specified, only pools with this allocation type will be returned.
	Valid inputs: static,dynamic

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
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$groupnet_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$groupnet_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][ValidateSet('static','dynamic')][string]$alloc_method,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('groupnet_id')){
				$parameter1 = $groupnet_id
			} else {
				$parameter1 = $groupnet_name
			}
			$parameter2 = $id
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'access_zone=' + $access_zone
			}
			if ($alloc_method){
				$queryArguments += 'alloc_method=' + $alloc_method
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
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/groupnets/$parameter1/subnets/$parameter2" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.pools,$ISIObject.resume
			}else{
				return $ISIObject.pools
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkGroupnetSubnetPools

function Get-isiNetworkInterfaces{
<#
.SYNOPSIS
	Get Network Interfaces

.DESCRIPTION
	Get a list of interfaces.

.PARAMETER alloc_method
	Filter addresses and owners by pool address allocation method.
	Valid inputs: dynamic,static

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER lnns
	Get a list of interfaces for the specified lnn.

.PARAMETER network
	Show interfaces associated with external and/or internal networks. Default is 'external'
	Valid inputs: all,external,internal

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('dynamic','static')][string]$alloc_method,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$lnns,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('all','external','internal')][string]$network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($alloc_method){
				$queryArguments += 'alloc_method=' + $alloc_method
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($lnns){
				$queryArguments += 'lnns=' + $lnns
			}
			if ($network){
				$queryArguments += 'network=' + $network
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/interfaces" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.interface,$ISIObject.resume
			}else{
				return $ISIObject.interface
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkInterfaces

function Get-isiNetworkPools{
<#
.SYNOPSIS
	Get Network Pools

.DESCRIPTION
	Get a list of flexnet pools.

.PARAMETER access_zone
	If specified, only pools with this zone name will be returned.

.PARAMETER alloc_method
	If specified, only pools with this allocation type will be returned.
	Valid inputs: static,dynamic

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER groupnet
	If specified, only pools for this groupnet will be returned.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER subnet
	If specified, only pools for this subnet will be returned.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('static','dynamic')][string]$alloc_method,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$subnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'access_zone=' + $access_zone
			}
			if ($alloc_method){
				$queryArguments += 'alloc_method=' + $alloc_method
			}
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($groupnet){
				$queryArguments += 'groupnet=' + $groupnet
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
			if ($subnet){
				$queryArguments += 'subnet=' + $subnet
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/pools" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.pools,$ISIObject.resume
			}else{
				return $ISIObject.pools
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkPools

function Get-isiNetworkRules{
<#
.SYNOPSIS
	Get Network Rules

.DESCRIPTION
	Get a list of network rules.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER groupnet
	Name of the groupnet to list rules from.

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER pool
	Name of the pool to list rules from.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER subnet
	Name of the subnet to list rules from.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('ASC','DESC')][string]$dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$groupnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$pool,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$subnet,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($dir){
				$queryArguments += 'dir=' + $dir
			}
			if ($groupnet){
				$queryArguments += 'groupnet=' + $groupnet
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
			}
			if ($pool){
				$queryArguments += 'pool=' + $pool
			}
			if ($resume){
				$queryArguments += 'resume=' + $resume
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($subnet){
				$queryArguments += 'subnet=' + $subnet
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/rules" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.rules,$ISIObject.resume
			}else{
				return $ISIObject.rules
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkRules

function Get-isiNetworkSubnets{
<#
.SYNOPSIS
	Get Network Subnets

.DESCRIPTION
	Get a list of subnets.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER groupnet
	If specified, only subnets for this groupnet will be returned.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$groupnet,
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
			if ($groupnet){
				$queryArguments += 'groupnet=' + $groupnet
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/network/subnets" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.subnets,$ISIObject.resume
			}else{
				return $ISIObject.subnets
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNetworkSubnets

function Get-isiFtpSettings{
<#
.SYNOPSIS
	Get Protocols Ftp Settings

.DESCRIPTION
	Retrieve the FTP settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ftp/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiFtpSettings

function Get-isiHdfsLogLevel{
<#
.SYNOPSIS
	Get Protocols Hdfs Log Level

.DESCRIPTION
	Retrieve the HDFS service log-level.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/hdfs/log-level" -Cluster $Cluster
			return $ISIObject.level
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsLogLevel

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
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

function Get-isiHdfsSettingsv3{
<#
.SYNOPSIS
	Get Protocols Hdfs Settings

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/hdfs/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHdfsSettingsv3

function Get-isiHttpSettings{
<#
.SYNOPSIS
	Get Protocols Http Settings

.DESCRIPTION
	Retrieve HTTP properties.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/http/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiHttpSettings

function Get-isiNdmpContextsBackup{
<#
.SYNOPSIS
	Get Protocols Ndmp Contexts Backup

.DESCRIPTION
	Get List of NDMP Backup Contexts.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/contexts/backup" -Cluster $Cluster
			return $ISIObject.contexts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpContextsBackup

function Get-isiNdmpContextsBackup{
<#
.SYNOPSIS
	Get Protocols Ndmp Contexts Backup

.DESCRIPTION
	View a NDMP backup context

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/contexts/backup/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpContextsBackup

function Get-isiNdmpContextsBre{
<#
.SYNOPSIS
	Get Protocols Ndmp Contexts Bre

.DESCRIPTION
	Get list of NDMP BRE Contexts.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/contexts/bre" -Cluster $Cluster
			return $ISIObject.contexts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpContextsBre

function Get-isiNdmpContextsBre{
<#
.SYNOPSIS
	Get Protocols Ndmp Contexts Bre

.DESCRIPTION
	View a NDMP BRE context

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/contexts/bre/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpContextsBre

function Get-isiNdmpContextsRestore{
<#
.SYNOPSIS
	Get Protocols Ndmp Contexts Restore

.DESCRIPTION
	Get List of NDMP Restore Contexts.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/contexts/restore" -Cluster $Cluster
			return $ISIObject.contexts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpContextsRestore

function Get-isiNdmpContextsRestore{
<#
.SYNOPSIS
	Get Protocols Ndmp Contexts Restore

.DESCRIPTION
	View a NDMP restore context

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/contexts/restore/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpContextsRestore

function Get-isiNdmpDiagnostics{
<#
.SYNOPSIS
	Get Protocols Ndmp Diagnostics

.DESCRIPTION
	List ndmp diagnostics settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/diagnostics" -Cluster $Cluster
			return $ISIObject.diagnostics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpDiagnostics

function Get-isiNdmpDumpdate{
<#
.SYNOPSIS
	Get Protocols Ndmp Dumpdate

.DESCRIPTION
	List of dumpdates entries.

.PARAMETER id
	Path id

.PARAMETER name
	Path name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/dumpdates/$parameter1" -Cluster $Cluster
			return $ISIObject.dumpdates
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpDumpdate

function Get-isiNdmpLogs{
<#
.SYNOPSIS
	Get Protocols Ndmp Logs

.DESCRIPTION
	Get NDMP logs

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/logs" -Cluster $Cluster
			return $ISIObject.logs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpLogs

function Get-isiNdmpSessions{
<#
.SYNOPSIS
	Get Protocols Ndmp Sessions

.DESCRIPTION
	List all ndmp sessions.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/sessions" -Cluster $Cluster
			return $ISIObject.sessions
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpSessions

function Get-isiNdmpSession{
<#
.SYNOPSIS
	Get Protocols Ndmp Session

.DESCRIPTION
	Retrieve the ndmp session.

.PARAMETER id
	Session id

.PARAMETER name
	Session name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/sessions/$parameter1" -Cluster $Cluster
			return $ISIObject.sessions
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpSession

function Get-isiNdmpSettingsDmas{
<#
.SYNOPSIS
	Get Protocols Ndmp Settings Dmas

.DESCRIPTION
	List of supported dma vendors.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/settings/dmas" -Cluster $Cluster
			return $ISIObject.dmavendors
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpSettingsDmas

function Get-isiNdmpSettingsGlobal{
<#
.SYNOPSIS
	Get Protocols Ndmp Settings Global

.DESCRIPTION
	List global ndmp settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/settings/global" -Cluster $Cluster
			return $ISIObject.global
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpSettingsGlobal

function Get-isiNdmpSettingsVariable{
<#
.SYNOPSIS
	Get Protocols Ndmp Settings Variable

.DESCRIPTION
	List of preferred environment variables.

.PARAMETER id
	Path id

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/settings/variables/$parameter1" -Cluster $Cluster
			return $ISIObject.variables
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpSettingsVariable

function Get-isiNdmpUsers{
<#
.SYNOPSIS
	Get Protocols Ndmp Users

.DESCRIPTION
	List all ndmp administrators.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/users" -Cluster $Cluster
			return $ISIObject.users
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpUsers

function Get-isiNdmpUser{
<#
.SYNOPSIS
	Get Protocols Ndmp User

.DESCRIPTION
	Retrieve the user.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ndmp/users/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNdmpUser

function Get-isiNfsAliases{
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiNfsAliases

function Get-isiNfsAlias{
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
	When specified as 'effective', or not specified, all fields are returned. When specified as 'user', only fields with non-default values are shown. When specified as 'default', the original values are returned.
	Valid inputs: effective,user

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiNfsAlias

function Get-isiNfsCheckv1{
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

Export-ModuleMember -Function Get-isiNfsCheckv1

function Get-isiNfsCheckv2{
<#
.SYNOPSIS
	Get Nfs Check

.DESCRIPTION
	Retrieve NFS export validation information.

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
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiNfsCheckv2
Set-Alias Get-isiNfsCheck -Value Get-isiNfsCheckv2
Export-ModuleMember -Alias Get-isiNfsCheck

function Get-isiNfsExportsv1{
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

Export-ModuleMember -Function Get-isiNfsExportsv1

function Get-isiNfsExportsv2{
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

.PARAMETER paths
	If specified, only exports that explicitly reference at least one of the given paths will be returned.

.PARAMETER resume
	Continue returning results from previous call using this token (token should come from the previous call, resume cannot be used with other options).

.PARAMETER scope
	When specified as 'effective', or not specified, all fields are returned. When specified as 'user', only fields with non-default values are shown. When specified as 'default', the original values are returned.
	Valid inputs: effective,user

.PARAMETER sort
	The field that will be used for sorting.

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($paths){
				$queryArguments += 'paths=' + $paths
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiNfsExportsv2
Set-Alias Get-isiNfsExports -Value Get-isiNfsExportsv2
Export-ModuleMember -Alias Get-isiNfsExports

function Get-isiNfsExportsSummaryv1{
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

Export-ModuleMember -Function Get-isiNfsExportsSummaryv1

function Get-isiNfsExportsSummaryv2{
<#
.SYNOPSIS
	Get Nfs Exports Summary

.DESCRIPTION
	Retrieve NFS export summary information.

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
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiNfsExportsSummaryv2
Set-Alias Get-isiNfsExportsSummary -Value Get-isiNfsExportsSummaryv2
Export-ModuleMember -Alias Get-isiNfsExportsSummary

function Get-isiNfsExportv1{
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
			$parameter1 = $id
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/1/protocols/nfs/exports/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.exports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExportv1

function Get-isiNfsExportv2{
<#
.SYNOPSIS
	Get Nfs Export

.DESCRIPTION
	Retrieve export information.

.PARAMETER id
	 id

.PARAMETER scope
	When specified as 'effective', or not specified, all fields are returned. When specified as 'user', only fields with non-default values are shown. When specified as 'default', the original values are returned.
	Valid inputs: effective,user

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][ValidateSet('effective','user')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$parameter1 = $id
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/2/protocols/nfs/exports/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.exports
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsExportv2
Set-Alias Get-isiNfsExport -Value Get-isiNfsExportv2
Export-ModuleMember -Alias Get-isiNfsExport

function Get-isiNfsLogLevel{
<#
.SYNOPSIS
	Get Protocols Nfs Log Level

.DESCRIPTION
	Get the current NFS service logging level.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/nfs/log-level" -Cluster $Cluster
			return $ISIObject.level
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsLogLevel

function Get-isiNfsNetgroup{
<#
.SYNOPSIS
	Get Protocols Nfs Netgroup

.DESCRIPTION
	Get the current NFS netgroup cache settings.

.PARAMETER host
	Host to retrieve netgroup cache settings from.

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
			$queryArguments = @()
			if ($host){
				$queryArguments += 'host=' + $host
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/nfs/netgroup" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNetgroup

function Get-isiNfsNlmLocksv1{
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

Export-ModuleMember -Function Get-isiNfsNlmLocksv1

function Get-isiNfsNlmLocksv2{
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

Export-ModuleMember -Function Get-isiNfsNlmLocksv2
Set-Alias Get-isiNfsNlmLocks -Value Get-isiNfsNlmLocksv2
Export-ModuleMember -Alias Get-isiNfsNlmLocks

function Get-isiNfsNlmSessionsv1{
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

Export-ModuleMember -Function Get-isiNfsNlmSessionsv1

function Get-isiNfsNlmSessionsv2{
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

Export-ModuleMember -Function Get-isiNfsNlmSessionsv2
Set-Alias Get-isiNfsNlmSessions -Value Get-isiNfsNlmSessionsv2
Export-ModuleMember -Alias Get-isiNfsNlmSessions

function Get-isiNfsNlmSessionsv3{
<#
.SYNOPSIS
	Get Protocols Nfs Nlm Sessions

.DESCRIPTION
	List all NSM clients (optionally filtered by either zone or IP)

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
			$queryArguments = @()
			if ($ip){
				$queryArguments += 'ip=' + $ip
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/nfs/nlm/sessions" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.clients
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmSessionsv3

function Get-isiNfsNlmSessionv3{
<#
.SYNOPSIS
	Get Protocols Nfs Nlm Session

.DESCRIPTION
	Retrieve all lock state for a single client.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER ip
	An IP address for which NSM has client records

.PARAMETER access_zone
	Represents an extant auth zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$ip,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($ip){
				$queryArguments += 'ip=' + $ip
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/nfs/nlm/sessions/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.sessions
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsNlmSessionv3

function Get-isiNfsNlmWaitersv1{
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

Export-ModuleMember -Function Get-isiNfsNlmWaitersv1

function Get-isiNfsNlmWaitersv2{
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

Export-ModuleMember -Function Get-isiNfsNlmWaitersv2
Set-Alias Get-isiNfsNlmWaiters -Value Get-isiNfsNlmWaitersv2
Export-ModuleMember -Alias Get-isiNfsNlmWaiters

function Get-isiNfsSettingsExportv1{
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

Export-ModuleMember -Function Get-isiNfsSettingsExportv1

function Get-isiNfsSettingsExportv2{
<#
.SYNOPSIS
	Get Nfs Settings Export

.DESCRIPTION
	Retrieve export information.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiNfsSettingsExportv2
Set-Alias Get-isiNfsSettingsExport -Value Get-isiNfsSettingsExportv2
Export-ModuleMember -Alias Get-isiNfsSettingsExport

function Get-isiNfsSettingsGlobalv3{
<#
.SYNOPSIS
	Get Protocols Nfs Settings Global

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/nfs/settings/global" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNfsSettingsGlobalv3

function Get-isiNfsSettingsZone{
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

Export-ModuleMember -Function Get-isiNfsSettingsZone

function Get-isiNtpServers{
<#
.SYNOPSIS
	Get Protocols Ntp Servers

.DESCRIPTION
	List all NTP servers.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/ntp/servers" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.servers,$ISIObject.resume
			}else{
				return $ISIObject.servers
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNtpServers

function Get-isiNtpServer{
<#
.SYNOPSIS
	Get Protocols Ntp Server

.DESCRIPTION
	Retrieve one NTP server.

.PARAMETER id
	Server id

.PARAMETER name
	Server name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ntp/servers/$parameter1" -Cluster $Cluster
			return $ISIObject.servers
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNtpServer

function Get-isiNtpSettings{
<#
.SYNOPSIS
	Get Protocols Ntp Settings

.DESCRIPTION
	Retrieve the NTP settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/ntp/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiNtpSettings

function Get-isiSmbLogLevel{
<#
.SYNOPSIS
	Get Protocols Smb Log Level

.DESCRIPTION
	Get the current SMB logging level.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/smb/log-level" -Cluster $Cluster
			return $ISIObject.level
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbLogLevel

function Get-isiSmbLogLevelFilters{
<#
.SYNOPSIS
	Get Protocols Smb Log Level Filters

.DESCRIPTION
	Get the current SMB log filters.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/smb/log-level/filters" -Cluster $Cluster
			return $ISIObject.filters
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbLogLevelFilters

function Get-isiSmbLogLevelFilter{
<#
.SYNOPSIS
	Get Protocols Smb Log Level Filter

.DESCRIPTION
	View log filter.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/smb/log-level/filters/$parameter1" -Cluster $Cluster
			return $ISIObject.filters
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbLogLevelFilter

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

function Get-isiSmbSettingsGlobalv1{
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

Export-ModuleMember -Function Get-isiSmbSettingsGlobalv1
Set-Alias Get-isiSmbSettingsGlobal -Value Get-isiSmbSettingsGlobalv1
Export-ModuleMember -Alias Get-isiSmbSettingsGlobal

function Get-isiSmbSettingsGlobalv3{
<#
.SYNOPSIS
	Get Protocols Smb Settings Global

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/smb/settings/global" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSettingsGlobalv3

function Get-isiSmbSettingsSharev1{
<#
.SYNOPSIS
	Get Smb Settings Share

.DESCRIPTION
	List all settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER access_zone
	Zone which contains these share settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiSmbSettingsSharev1
Set-Alias Get-isiSmbSettingsShare -Value Get-isiSmbSettingsSharev1
Export-ModuleMember -Alias Get-isiSmbSettingsShare

function Get-isiSmbSettingsSharev3{
<#
.SYNOPSIS
	Get Protocols Smb Settings Share

.DESCRIPTION
	List all settings.

.PARAMETER scope
	If specified as "effective" or not specified, all fields are returned.  If specified as "user", only fields with non-default values are shown.  If specified as "default", the original values are returned.
	Valid inputs: user,default,effective

.PARAMETER access_zone
	Zone which contains these share settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][ValidateSet('user','default','effective')][string]$scope,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/smb/settings/share" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSettingsSharev3

function Get-isiSmbSharesv1{
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$access_zone,
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiSmbSharesv1
Set-Alias Get-isiSmbShares -Value Get-isiSmbSharesv1
Export-ModuleMember -Alias Get-isiSmbShares

function Get-isiSmbSharesv3{
<#
.SYNOPSIS
	Get Protocols Smb Shares

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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$access_zone,
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/smb/shares" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.shares,$ISIObject.resume
			}else{
				return $ISIObject.shares
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSharesv3

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

function Get-isiSmbSharev1{
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

Export-ModuleMember -Function Get-isiSmbSharev1
Set-Alias Get-isiSmbShare -Value Get-isiSmbSharev1
Export-ModuleMember -Alias Get-isiSmbShare

function Get-isiSmbSharev3{
<#
.SYNOPSIS
	Get Protocols Smb Share

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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/protocols/smb/shares/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.shares
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSmbSharev3

function Get-isiSnmpSettings{
<#
.SYNOPSIS
	Get Protocols Snmp Settings

.DESCRIPTION
	Retrieve the SNMP settings.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/snmp/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnmpSettings

function Get-isiSwiftAccounts{
<#
.SYNOPSIS
	Get Protocols Swift Accounts

.DESCRIPTION
	List all swift accounts.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/swift/accounts" -Cluster $Cluster
			return $ISIObject.accounts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSwiftAccounts

function Get-isiSwiftAccount{
<#
.SYNOPSIS
	Get Protocols Swift Account

.DESCRIPTION
	List a swift account.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/protocols/swift/accounts/$parameter1" -Cluster $Cluster
			return $ISIObject.accounts
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSwiftAccount

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

.PARAMETER enforced
	Only list quotas with this enforcement (non-accounting).

.PARAMETER exceeded
	Set to true to only list quotas which have exceeded one or more of their thresholds.

.PARAMETER include_snapshots
	Only list quotas with this setting for include_snapshots.

.PARAMETER limit
	Return no more than this many results at once (see resume).

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

.PARAMETER access_zone
	Optional named zone to use for user and group resolution.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$enforced,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$exceeded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$include_snapshots,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$persona,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][bool]$recurse_path_children,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][bool]$recurse_path_parents,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$report_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][bool]$resolve_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$resume,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][ValidateSet('directory','user','group','default-user','default-group')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($enforced){
				$queryArguments += 'enforced=' + $enforced
			}
			if ($exceeded){
				$queryArguments += 'exceeded=' + $exceeded
			}
			if ($include_snapshots){
				$queryArguments += 'include_snapshots=' + $include_snapshots
			}
			if ($limit){
				$queryArguments += 'limit=' + $limit
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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

.PARAMETER access_zone
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($resolve_names){
				$queryArguments += 'resolve_names=' + $resolve_names
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($contents){
				$queryArguments += 'contents=' + $contents
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

function Get-isiSnapshotSchedulesv1{
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

Export-ModuleMember -Function Get-isiSnapshotSchedulesv1
Set-Alias Get-isiSnapshotSchedules -Value Get-isiSnapshotSchedulesv1
Export-ModuleMember -Alias Get-isiSnapshotSchedules

function Get-isiSnapshotSchedulesv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/snapshot/schedules" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.schedules,$ISIObject.resume
			}else{
				return $ISIObject.schedules
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSnapshotSchedulesv3

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
			if ($psBoundParameters.ContainsKey('snapshot_id')){
				$parameter1 = $snapshot_id
			} else {
				$parameter1 = $snapshot_name
			}
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
	Node devid to query. Either an <integer> or "all". Can be used more than one time to query multiple nodes. "all" queries all up nodes. 0 means query the local node. For "cluster" scoped keys, in any devid including 0 can be used.

.PARAMETER expand_clientid
	If true, use name resolution to expand client addresses and other IDs.

.PARAMETER key
	One key name. Can be used more than one time to query multiple keys. Also works with 'keys' arguments.

.PARAMETER keys
	Multiple key names. May request matching keys or request 'all' keys. Can be comma separated list or can be used more than one time to make queries for multiple keys. May be used in conjunction with 'substr'. Also works with 'key' arguments.

.PARAMETER substr
	Used in conjunction with the 'keys' argument, alters the behavior of keys. Makes the 'keys' arg perform a partial match. Defaults to false.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][array]$keys,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$substr,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($keys){
				$queryArguments += 'keys=' + $keys
			}
			if ($substr){
				$queryArguments += 'substr=' + $substr
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
	Node devid to query. Either an <integer> or "all". Can be used more than one time to query multiple nodes. "all" queries all up nodes. 0 means query the local node. For "cluster" scoped keys, in any devid including 0 can be used.

.PARAMETER end
	Latest time (Unix epoch seconds) of interest. Negative times are interpreted as relative (before) now. If not supplied, use now as the end time.

.PARAMETER expand_clientid
	If true, use name resolution to expand client addresses and other IDs.

.PARAMETER interval
	Minimum sampling interval time in seconds. If native statistics are higher resolution, data will be down-sampled.

.PARAMETER key
	One key name. Can be used more than one time to query multiple keys. Also works with 'keys' arguments.

.PARAMETER keys
	Multiple key names. May request matching keys or request 'all' keys. Can be comma separated list or can be used more than one time to make queries for multiple keys. May be used in conjunction with 'substr'. Also works with 'key' arguments.

.PARAMETER memory_only
	Only use statistics sources that reside in memory (faster, but with less retention).

.PARAMETER resolution
	Synonymous with 'interval', if supplied supersedes interval.

.PARAMETER substr
	Used in conjunction with the 'keys' argument, alters the behavior of keys. Makes the 'keys' arg perform a partial match. Defaults to false.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][array]$keys,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][bool]$memory_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][int]$resolution,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][bool]$substr,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($keys){
				$queryArguments += 'keys=' + $keys
			}
			if ($memory_only){
				$queryArguments += 'memory_only=' + $memory_only
			}
			if ($resolution){
				$queryArguments += 'resolution=' + $resolution
			}
			if ($substr){
				$queryArguments += 'substr=' + $substr
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

function Get-isiStatisticsOperations{
<#
.SYNOPSIS
	Get Statistics Operations

.DESCRIPTION
	Retrieve operations list.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/statistics/operations" -Cluster $Cluster
			return $ISIObject.operations
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsOperations

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

function Get-isiStatisticsSummaryClient{
<#
.SYNOPSIS
	Get Statistics Summary Client

.DESCRIPTION
	

.PARAMETER classes
	Specify class(es) for which statistics should be reported. Default is all supported classes.

.PARAMETER degraded
	Continue to report if some nodes do not respond.

.PARAMETER local_addrs
	A comma seperated list. Only report statistics for operations handled by the local hosts with dotted-quad IP addresses enumerated.

.PARAMETER local_names
	A comma seperated list. Only report statistics for operations handled by the local hosts with resolved names enumerated.

.PARAMETER nodes
	A comma seperated list. Specify node(s) for which statistics should be reported. Default is 'all'. Zero (0) should be passed in as the sole argument to indicate local.

.PARAMETER numeric
	Whether to convert hostnames or usernames to their human readable form. False by default.

.PARAMETER protocols
	A comma seperated list of the protocol(s) you wish to return. Default is 'all' of the folowing: nfs3|smb1|nlm|ftp|http|siq|iscsi|smb2|nfs4|papi|jobd|irp|lsass_in|lsass_out|hdfs|internal|external

.PARAMETER remote_addrs
	A comma seperated list. Only report statistics for operations requested by the remote clients with dotted-quad IP addresses enumerated.

.PARAMETER remote_names
	A comma seperated list. Only report statistics for operations requested by the remote clients with resolved names enumerated.

.PARAMETER sort
	{ drive_id | type | xfers_in | bytes_in | xfer_size_in | xfers_out | bytes_out | xfer_size_out | access_latency | access_slow | iosched_latency | iosched_queue | busy | used_bytes_percent | used_inodes } Sort data by the specified comma-separated field(s). Prepend 'asc:' or 'desc:' to a field to change the sort direction.

.PARAMETER timeout
	Timeout remote commands after NUM seconds, where NUM is the integer passed to the argument.

.PARAMETER totalby
	A comma separated list specifying what should be unique. node|protocol|class|local_addr|local_name|remote_addr|remote_name|user_id|user_name|devid

.PARAMETER user_ids
	A comma seperated list. Only report statistics for operations requested by users with numeric UIDs enumerated.

.PARAMETER user_names
	A comma seperated list. Only report statistics for operations requested by users with resolved names enumerated.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$classes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$local_addrs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$local_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][bool]$numeric,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$protocols,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$remote_addrs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$remote_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$totalby,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$user_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateNotNullOrEmpty()][string]$user_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($classes){
				$queryArguments += 'classes=' + $classes
			}
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($local_addrs){
				$queryArguments += 'local_addrs=' + $local_addrs
			}
			if ($local_names){
				$queryArguments += 'local_names=' + $local_names
			}
			if ($nodes){
				$queryArguments += 'nodes=' + $nodes
			}
			if ($numeric){
				$queryArguments += 'numeric=' + $numeric
			}
			if ($protocols){
				$queryArguments += 'protocols=' + $protocols
			}
			if ($remote_addrs){
				$queryArguments += 'remote_addrs=' + $remote_addrs
			}
			if ($remote_names){
				$queryArguments += 'remote_names=' + $remote_names
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($totalby){
				$queryArguments += 'totalby=' + $totalby
			}
			if ($user_ids){
				$queryArguments += 'user_ids=' + $user_ids
			}
			if ($user_names){
				$queryArguments += 'user_names=' + $user_names
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/statistics/summary/client" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.client
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsSummaryClient

function Get-isiStatisticsSummaryDrive{
<#
.SYNOPSIS
	Get Statistics Summary Drive

.DESCRIPTION
	

.PARAMETER degraded
	Continue to report if some nodes do not respond.

.PARAMETER nodes
	Specify node(s) for which statistics should be reported. A comma separated set of numbers. Default is 'all'. Zero (0) should be passed in as the sole argument to indicate only the local node.

.PARAMETER sort
	{ drive_id | type | xfers_in | bytes_in | xfer_size_in | xfers_out | bytes_out | xfer_size_out | access_latency | access_slow | iosched_latency | iosched_queue | busy | used_bytes_percent | used_inodes } Sort data by the specified comma-separated field(s). Prepend 'asc:' or 'desc:' to a field to change the sort direction.

.PARAMETER timeout
	Timeout remote commands after NUM seconds, where NUM is the integer passed to the argument.

.PARAMETER type
	Specify drive type(s) for which statistics should be reported.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($nodes){
				$queryArguments += 'nodes=' + $nodes
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($type){
				$queryArguments += 'type=' + $type
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/statistics/summary/drive" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.drive
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsSummaryDrive

function Get-isiStatisticsSummaryHeat{
<#
.SYNOPSIS
	Get Statistics Summary Heat

.DESCRIPTION
	File heat map, i.e. rate of file operations, and the type of operation listed by path/lin(s).

.PARAMETER classes
	Specify class(es) for which statistics should be reported. Default is all supported classes. See [...]/platform/3/statistics/summary/filters/classes for a complete list.

.PARAMETER convertlin
	Convert lin to hex. Defaults to true.

.PARAMETER degraded
	Continue to report if some nodes do not respond.

.PARAMETER events
	Only report specified event types(s). A comma separated list of events. Defaults to all supported events. See [...]/platform/3/statistics/summary/filters/events for a complete list.

.PARAMETER maxpath
	Maximum bytes allocated for looking up a path. An ASCII character is 1 byte (It may be more for other types of encoding). The default is 1024 bytes. Zero (0) means unlimited (Subject to the system limits.)

.PARAMETER nodes
	Specify node(s) for which statistics should be reported. A comma separated set of numbers. Default is 'all'. Zero (0) should be passed in as the sole argument to indicate only the local node.

.PARAMETER numeric
	Whether to convert hostnames or usernames to their human readable form. False by default.

.PARAMETER pathdepth
	Squash paths to this directory depth. Defaults to none, ie. the paths are not limited (Subject to the system limits.)

.PARAMETER sort
	{ drive_id | type | xfers_in | bytes_in | xfer_size_in | xfers_out | bytes_out | xfer_size_out | access_latency | access_slow | iosched_latency | iosched_queue | busy | used_bytes_percent | used_inodes } Sort data by the specified comma-separated field(s). Prepend 'asc:' or 'desc:' to a field to change the sort direction.

.PARAMETER timeout
	Timeout remote commands after NUM seconds, where NUM is the integer passed to the argument.

.PARAMETER totalby
	Aggregate per specified fields(s). Defaults to none.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$classes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$convertlin,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$events,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][int]$maxpath,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][bool]$numeric,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][int]$pathdepth,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$totalby,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($classes){
				$queryArguments += 'classes=' + $classes
			}
			if ($convertlin){
				$queryArguments += 'convertlin=' + $convertlin
			}
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($events){
				$queryArguments += 'events=' + $events
			}
			if ($maxpath){
				$queryArguments += 'maxpath=' + $maxpath
			}
			if ($nodes){
				$queryArguments += 'nodes=' + $nodes
			}
			if ($numeric){
				$queryArguments += 'numeric=' + $numeric
			}
			if ($pathdepth){
				$queryArguments += 'pathdepth=' + $pathdepth
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($totalby){
				$queryArguments += 'totalby=' + $totalby
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/statistics/summary/heat" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.heat
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsSummaryHeat

function Get-isiStatisticsSummaryProtocol{
<#
.SYNOPSIS
	Get Statistics Summary Protocol

.DESCRIPTION
	

.PARAMETER classes
	Specify class(es) for which statistics should be reported. Default is all supported classes. See [...]/platform/3/statistics/summary/filters/classes for a complete list.

.PARAMETER degraded
	Continue to report if some nodes do not respond.

.PARAMETER nodes
	Specify node(s) for which statistics should be reported. A comma separated set of numbers. Default is 'all'. Zero (0) should be passed in as the sole argument to indicate only the local node.

.PARAMETER operations
	Specify operation(s) for which statistics should be reported. Default is all operations. See isi-statistics man page for complete listing of operations.

.PARAMETER protocol
	Specify protocol(s) for which statistics should be reported. Default is all external protocols.

.PARAMETER sort
	{ drive_id | type | xfers_in | bytes_in | xfer_size_in | xfers_out | bytes_out | xfer_size_out | access_latency | access_slow | iosched_latency | iosched_queue | busy | used_bytes_percent | used_inodes } Sort data by the specified comma-separated field(s). Prepend 'asc:' or 'desc:' to a field to change the sort direction.

.PARAMETER timeout
	Timeout remote commands after NUM seconds, where NUM is the integer passed to the argument.

.PARAMETER totalby
	Aggregate per specified fields(s). Defaults to none.

.PARAMETER zero
	Show table entries with no values.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][string]$classes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$operations,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$protocol,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$sort,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$totalby,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][bool]$zero,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($classes){
				$queryArguments += 'classes=' + $classes
			}
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($nodes){
				$queryArguments += 'nodes=' + $nodes
			}
			if ($operations){
				$queryArguments += 'operations=' + $operations
			}
			if ($protocol){
				$queryArguments += 'protocol=' + $protocol
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($totalby){
				$queryArguments += 'totalby=' + $totalby
			}
			if ($zero){
				$queryArguments += 'zero=' + $zero
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/statistics/summary/protocol" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.protocol
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsSummaryProtocol

function Get-isiStatisticsSummaryProtocolStats{
<#
.SYNOPSIS
	Get Statistics Summary Protocol Stats

.DESCRIPTION
	

.PARAMETER degraded
	Continue to report if some nodes do not respond.

.PARAMETER nodes
	Specify node(s) for which statistics should be reported. A comma separated set of numbers. Default is 'all'. Zero (0) should be passed in as the sole argument to indicate only the local node.

.PARAMETER protocol
	Specify protocol(s) for which statistics should be reported. Default is all external protocols.

.PARAMETER timeout
	Timeout remote commands after NUM seconds, where NUM is the integer passed to the argument.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$protocol,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][int]$timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($degraded){
				$queryArguments += 'degraded=' + $degraded
			}
			if ($nodes){
				$queryArguments += 'nodes=' + $nodes
			}
			if ($protocol){
				$queryArguments += 'protocol=' + $protocol
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/statistics/summary/protocol-stats" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.'protocol-stats'
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsSummaryProtocolStats

function Get-isiStatisticsSummarySystem{
<#
.SYNOPSIS
	Get Statistics Summary System

.DESCRIPTION
	

.PARAMETER degraded
	Continue to report if some nodes do not respond.

.PARAMETER nodes
	Specify node(s) for which statistics should be reported. A comma separated set of numbers. Default is 'all'. Zero (0) should be passed in as the sole argument to indicate only the local node.

.PARAMETER oprates
	Display protocol operation rate statistics rather than the default throughput statistics.

.PARAMETER sort
	{ drive_id | type | xfers_in | bytes_in | xfer_size_in | xfers_out | bytes_out | xfer_size_out | access_latency | access_slow | iosched_latency | iosched_queue | busy | used_bytes_percent | used_inodes } Sort data by the specified comma-separated field(s). Prepend 'asc:' or 'desc:' to a field to change the sort direction.

.PARAMETER timeout
	Timeout remote commands after NUM seconds, where NUM is the integer passed to the argument.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$degraded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$oprates,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$sort,
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
			if ($nodes){
				$queryArguments += 'nodes=' + $nodes
			}
			if ($oprates){
				$queryArguments += 'oprates=' + $oprates
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($timeout){
				$queryArguments += 'timeout=' + $timeout
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/statistics/summary/system" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.system
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStatisticsSummarySystem

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

function Get-isiStoragepoolCompatibilitiesSSDActivev1{
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

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDActivev1
Set-Alias Get-isiStoragepoolCompatibilitiesSSDActive -Value Get-isiStoragepoolCompatibilitiesSSDActivev1
Export-ModuleMember -Alias Get-isiStoragepoolCompatibilitiesSSDActive

function Get-isiStoragepoolCompatibilitiesSSDActivev3{
<#
.SYNOPSIS
	Get Storagepool Compatibilities Ssd Active

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/storagepool/compatibilities/ssd/active" -Cluster $Cluster
			return $ISIObject.active
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDActivev3

function Get-isiStoragepoolCompatibilitiesSSDActiveIdv1{
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

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDActiveIdv1
Set-Alias Get-isiStoragepoolCompatibilitiesSSDActiveId -Value Get-isiStoragepoolCompatibilitiesSSDActiveIdv1
Export-ModuleMember -Alias Get-isiStoragepoolCompatibilitiesSSDActiveId

function Get-isiStoragepoolCompatibilitiesSSDActivev3{
<#
.SYNOPSIS
	Get Storagepool Compatibilities Ssd Active

.DESCRIPTION
	Get a active ssd compatibilities by id

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/storagepool/compatibilities/ssd/active/$parameter1" -Cluster $Cluster
			return $ISIObject.active
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDActivev3

function Get-isiStoragepoolCompatibilitiesSSDAvailablev1{
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

Export-ModuleMember -Function Get-isiStoragepoolCompatibilitiesSSDAvailablev1
Set-Alias Get-isiStoragepoolCompatibilitiesSSDAvailable -Value Get-isiStoragepoolCompatibilitiesSSDAvailablev1
Export-ModuleMember -Alias Get-isiStoragepoolCompatibilitiesSSDAvailable

function Get-isiStoragepoolNodepoolsv1{
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

Export-ModuleMember -Function Get-isiStoragepoolNodepoolsv1
Set-Alias Get-isiStoragepoolNodepools -Value Get-isiStoragepoolNodepoolsv1
Export-ModuleMember -Alias Get-isiStoragepoolNodepools

function Get-isiStoragepoolNodepoolsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/storagepool/nodepools" -Cluster $Cluster
			return $ISIObject.nodepools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolNodepoolsv3

function Get-isiStoragepoolNodepoolv1{
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

Export-ModuleMember -Function Get-isiStoragepoolNodepoolv1
Set-Alias Get-isiStoragepoolNodepool -Value Get-isiStoragepoolNodepoolv1
Export-ModuleMember -Alias Get-isiStoragepoolNodepool

function Get-isiStoragepoolNodepoolv3{
<#
.SYNOPSIS
	Get Storagepool Nodepool

.DESCRIPTION
	Retrieve node pool information.

.PARAMETER id
	Nid id

.PARAMETER name
	Nid name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/storagepool/nodepools/$parameter1" -Cluster $Cluster
			return $ISIObject.nodepools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolNodepoolv3

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

function Get-isiStoragepoolsv1{
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

Export-ModuleMember -Function Get-isiStoragepoolsv1
Set-Alias Get-isiStoragepools -Value Get-isiStoragepoolsv1
Export-ModuleMember -Alias Get-isiStoragepools

function Get-isiStoragepoolStoragepoolsv3{
<#
.SYNOPSIS
	Get Storagepool Storagepools

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/storagepool/storagepools" -Cluster $Cluster
			return $ISIObject.storagepools
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolStoragepoolsv3

function Get-isiStoragepoolSuggestedProtection{
<#
.SYNOPSIS
	Get Storagepool Suggested Protection

.DESCRIPTION
	Retrieve the suggested protection policy.

.PARAMETER id
	Nid id

.PARAMETER name
	Nid name

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/storagepool/suggested-protection/$parameter1" -Cluster $Cluster
			return $ISIObject.suggested_protection
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiStoragepoolSuggestedProtection

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
	Get the unprovisioned nodes and drives

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

function Get-isiSyncHistoryCpu{
<#
.SYNOPSIS
	Get Sync History Cpu

.DESCRIPTION
	List cpu performance data.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/sync/history/cpu" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.statistics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncHistoryCpu

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

function Get-isiSyncHistoryWorker{
<#
.SYNOPSIS
	Get Sync History Worker

.DESCRIPTION
	List worker performance data.

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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/sync/history/worker" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.statistics
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncHistoryWorker

function Get-isiSyncJobsv1{
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
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,skipped,pending,unknown

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','skipped','pending','unknown')][string]$state,
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

Export-ModuleMember -Function Get-isiSyncJobsv1
Set-Alias Get-isiSyncJobs -Value Get-isiSyncJobsv1
Export-ModuleMember -Alias Get-isiSyncJobs

function Get-isiSyncJobsv3{
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
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,skipped,pending,unknown

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','skipped','pending','unknown')][string]$state,
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/sync/jobs" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.jobs,$ISIObject.resume
			}else{
				return $ISIObject.jobs
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncJobsv3

function Get-isiSyncJobv1{
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

Export-ModuleMember -Function Get-isiSyncJobv1
Set-Alias Get-isiSyncJob -Value Get-isiSyncJobv1
Export-ModuleMember -Alias Get-isiSyncJob

function Get-isiSyncJobv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/sync/jobs/$parameter1" -Cluster $Cluster
			return $ISIObject.jobs
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncJobv3

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

function Get-isiSyncPoliciesv1{
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

Export-ModuleMember -Function Get-isiSyncPoliciesv1
Set-Alias Get-isiSyncPolicies -Value Get-isiSyncPoliciesv1
Export-ModuleMember -Alias Get-isiSyncPolicies

function Get-isiSyncPoliciesv3{
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
			if ($scope){
				$queryArguments += 'scope=' + $scope
			}
			if ($sort){
				$queryArguments += 'sort=' + $sort
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/sync/policies" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.policies,$ISIObject.resume
			}else{
				return $ISIObject.policies
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncPoliciesv3

function Get-isiSyncPolicyv1{
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

Export-ModuleMember -Function Get-isiSyncPolicyv1
Set-Alias Get-isiSyncPolicy -Value Get-isiSyncPolicyv1
Export-ModuleMember -Alias Get-isiSyncPolicy

function Get-isiSyncPolicyv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/sync/policies/$parameter1" -Cluster $Cluster
			return $ISIObject.policies
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncPolicyv3

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
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,skipped,pending,unknown

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','skipped','pending','unknown')][string]$state,
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
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,skipped,pending,unknown

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','skipped','pending','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('report_id')){
				$parameter1 = $report_id
			} else {
				$parameter1 = $report_name
			}
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

function Get-isiSyncRulesv1{
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

Export-ModuleMember -Function Get-isiSyncRulesv1
Set-Alias Get-isiSyncRules -Value Get-isiSyncRulesv1
Export-ModuleMember -Alias Get-isiSyncRules

function Get-isiSyncRulesv3{
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
	Valid inputs: bandwidth,file_count,cpu,worker

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][ValidateSet('bandwidth','file_count','cpu','worker')][string]$type,
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/sync/rules" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.rules,$ISIObject.resume
			}else{
				return $ISIObject.rules
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncRulesv3

function Get-isiSyncRulev1{
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

Export-ModuleMember -Function Get-isiSyncRulev1
Set-Alias Get-isiSyncRule -Value Get-isiSyncRulev1
Export-ModuleMember -Alias Get-isiSyncRule

function Get-isiSyncRulev3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/sync/rules/$parameter1" -Cluster $Cluster
			return $ISIObject.rules
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncRulev3

function Get-isiSyncSettingsv1{
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

Export-ModuleMember -Function Get-isiSyncSettingsv1
Set-Alias Get-isiSyncSettings -Value Get-isiSyncSettingsv1
Export-ModuleMember -Alias Get-isiSyncSettings

function Get-isiSyncSettingsv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/sync/settings" -Cluster $Cluster
			return $ISIObject.settings
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiSyncSettingsv3

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
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,skipped,pending,unknown

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','skipped','pending','unknown')][string]$state,
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
	Valid inputs: scheduled,running,paused,finished,failed,canceled,needs_attention,skipped,pending,unknown

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][ValidateSet('scheduled','running','paused','finished','failed','canceled','needs_attention','skipped','pending','unknown')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('report_id')){
				$parameter1 = $report_id
			} else {
				$parameter1 = $report_name
			}
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

function Get-isiUpgradeCluster{
<#
.SYNOPSIS
	Get Upgrade Cluster

.DESCRIPTION
	Cluster wide upgrade status info.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/upgrade/cluster" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeCluster

function Get-isiUpgradeClusterFirmwareProgress{
<#
.SYNOPSIS
	Get Upgrade Cluster Firmware Progress

.DESCRIPTION
	Cluster wide firmware upgrade status info.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/upgrade/cluster/firmware/progress" -Cluster $Cluster
			return $ISIObject.cluster_state
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterFirmwareProgress

function Get-isiUpgradeClusterFirmwareStatus{
<#
.SYNOPSIS
	Get Upgrade Cluster Firmware Status

.DESCRIPTION
	The firmware status for the cluster.

.PARAMETER devices
	Show devices. If false, this returns an empty list. Default is false.

.PARAMETER package
	Show package. If false, this returns an empty list.Default is false.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateNotNullOrEmpty()][bool]$devices,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$package,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$queryArguments = @()
			if ($devices){
				$queryArguments += 'devices=' + $devices
			}
			if ($package){
				$queryArguments += 'package=' + $package
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/upgrade/cluster/firmware/status" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterFirmwareStatus

function Get-isiUpgradeClusterNodes{
<#
.SYNOPSIS
	Get Upgrade Cluster Nodes

.DESCRIPTION
	View information about nodes during an upgrade, rollback, or pre-upgrade assessment.

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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/upgrade/cluster/nodes" -Cluster $Cluster
			return $ISIObject.nodes
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterNodes

function Get-isiUpgradeClusterNode{
<#
.SYNOPSIS
	Get Upgrade Cluster Node

.DESCRIPTION
	The node details useful during an upgrade or assessment.

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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/upgrade/cluster/nodes/$parameter1" -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterNode

function Get-isiUpgradeClusterNodeFirmwareStatus{
<#
.SYNOPSIS
	Get Upgrade Cluster Node Firmware Status

.DESCRIPTION
	The firmware status for the node.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER devices
	Show devices. If false, this returns an empty list. Default is false.

.PARAMETER package
	Show package. If false, this returns an empty list.Default is false.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$devices,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$package,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
			} else {
				$parameter1 = $name
			}
			$queryArguments = @()
			if ($devices){
				$queryArguments += 'devices=' + $devices
			}
			if ($package){
				$queryArguments += 'package=' + $package
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/upgrade/cluster/nodes/$parameter1/firmware/status" + "$queryArguments") -Cluster $Cluster
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterNodeFirmwareStatus

function Get-isiUpgradeClusterPatchPatches{
<#
.SYNOPSIS
	Get Upgrade Cluster Patch Patches

.DESCRIPTION
	List all patches.

.PARAMETER dir
	The direction of the sort.
	Valid inputs: ASC,DESC

.PARAMETER limit
	Return no more than this many results at once (see resume).

.PARAMETER local
	Whether to view patches on the local node only.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][bool]$local,
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
			if ($local){
				$queryArguments += 'local=' + $local
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
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/upgrade/cluster/patch/patches" + "$queryArguments") -Cluster $Cluster
			if ($ISIObject.PSObject.Properties['resume'] -and ($resume -or $limit)){
				return $ISIObject.patches,$ISIObject.resume
			}else{
				return $ISIObject.patches
			}
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterPatchPatches

function Get-isiUpgradeClusterPatchPatche{
<#
.SYNOPSIS
	Get Upgrade Cluster Patch Patche

.DESCRIPTION
	View a single patch.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER local
	Only view patch information on the local node.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][bool]$local,
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
			$queryArguments = @()
			if ($local){
				$queryArguments += 'local=' + $local
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			$ISIObject = Send-isiAPI -Method GET -Resource ("/platform/3/upgrade/cluster/patch/patches/$parameter1" + "$queryArguments") -Cluster $Cluster
			return $ISIObject.patches
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiUpgradeClusterPatchPatche

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

function Get-isiZonesv1{
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

Export-ModuleMember -Function Get-isiZonesv1
Set-Alias Get-isiZones -Value Get-isiZonesv1
Export-ModuleMember -Alias Get-isiZones

function Get-isiZonesv3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/zones" -Cluster $Cluster
			return $ISIObject.zones
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiZonesv3

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

function Get-isiZonev1{
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

Export-ModuleMember -Function Get-isiZonev1
Set-Alias Get-isiZone -Value Get-isiZonev1
Export-ModuleMember -Alias Get-isiZone

function Get-isiZonev3{
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
			$ISIObject = Send-isiAPI -Method GET -Resource "/platform/3/zones/$parameter1" -Cluster $Cluster
			return $ISIObject.zones
	}
	End{
	}
}

Export-ModuleMember -Function Get-isiZonev3


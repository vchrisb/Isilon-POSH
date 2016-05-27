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

#Build using Isilon OneFS build: B_MR_8_0_0_1_131(RELEASE)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


function Set-isiAntivirusPolicy{
<#
.SYNOPSIS
	Set Antivirus Policy

.DESCRIPTION
	Modify an antivirus scan policy.

.PARAMETER id
	Name id

.PARAMETER name
	Name name

.PARAMETER description
	A description for the policy.

.PARAMETER enabled
	Whether the policy is enabled.

.PARAMETER force_run
	Forces the scan to run regardless of whether the files were recently scanned.

.PARAMETER impact
	The priority of the antivirus scan job.  Must be a valid job engine impact policy, or null to use the default impact.

.PARAMETER new_name
	The name of the policy.

.PARAMETER paths
	Paths to include in the scan.

.PARAMETER recursion_depth
	The depth to recurse in directories.  The default of -1 gives unlimited recursion.

.PARAMETER schedule
	The schedule for running scans in isi date format.  Examples include: 'every Friday' or 'every day at 4:00'.  A null value means the policy is manually scheduled.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$force_run,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$impact,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$recursion_depth,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAntivirusPolicy')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/antivirus/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAntivirusPolicy

function Set-isiAntivirusQuarantine{
<#
.SYNOPSIS
	Set Antivirus Quarantine

.DESCRIPTION
	Set the quarantine status of the file at the specified path.  Use either an empty object {} in the request body or {"quarantined":true} to quarantine the file, and {"quarantined":false} to unquarantine the file.

.PARAMETER id
	Path id

.PARAMETER name
	Path name

.PARAMETER quarantined
	If true, this file is quarantined.  If false, the file is not quarantined.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$quarantined,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAntivirusQuarantine')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/antivirus/quarantine/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAntivirusQuarantine

function Set-isiAntivirusServer{
<#
.SYNOPSIS
	Set Antivirus Server

.DESCRIPTION
	Modify an antivirus server entry.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER description
	A description for the server.

.PARAMETER enabled
	Whether the server is enabled.

.PARAMETER url
	The icap url for the server.  This should have a format of: icap://host.domain:port/path

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$url,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAntivirusServer')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/antivirus/servers/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAntivirusServer

function Set-isiAntivirusSettings{
<#
.SYNOPSIS
	Set Antivirus Settings

.DESCRIPTION
	Modify the Antivirus settings. All input fields are optional, but one or more must be supplied.

.PARAMETER fail_open
	Allow access when scanning fails.

.PARAMETER glob_filters
	Glob patterns for leaf filenames.

.PARAMETER glob_filters_enabled
	Enable glob filters.

.PARAMETER glob_filters_include
	If true, only scan files matching a glob filter. If false, only scan files that don't match a glob filter.

.PARAMETER path_prefixes
	Paths to include in realtime scans.

.PARAMETER quarantine
	Try to quarantine files when threats are found.

.PARAMETER repair
	Try to repair files when threats are found.

.PARAMETER report_expiry
	Amount of time in seconds until old reporting data is purged.

.PARAMETER scan_on_close
	Scan files when apps close them.

.PARAMETER scan_on_open
	Scan files on access.

.PARAMETER scan_size_maximum
	Skip scanning files larger than this.

.PARAMETER service
	Whether the antivirus service is enabled.

.PARAMETER truncate
	Try to truncate files when threats are found.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$fail_open,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$glob_filters,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$glob_filters_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$glob_filters_include,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$path_prefixes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$quarantine,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$repair,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$report_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$scan_on_close,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$scan_on_open,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$scan_size_maximum,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$truncate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=13)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAntivirusSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/antivirus/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAntivirusSettings

function Set-isiAuditSettingsGlobalv1{
<#
.SYNOPSIS
	Set Audit Global Settings

.DESCRIPTION
	Modify Global Audit settings.

.PARAMETER audited_zones
	Specifies zones that are audited when the protocol_auditing_enabled property is enabled.

.PARAMETER cee_log_time
	Specifies that events past a certain date are forwarded by the audit CEE forwarder. Format these events as follows: 'Topic@YYYY-MM-DD HH:MM:SS'.

.PARAMETER cee_server_uris
	Specifies a list of Common Event Enabler (CEE) server URIs. Protocol audit logs are sent to these URIs for external processing.

.PARAMETER config_auditing_enabled
	Specifies whether logging for API configuration changes are enabled.

.PARAMETER config_syslog_enabled
	Specifies whether configuration audit syslog messages are forwarded.

.PARAMETER hostname
	Specifies the hostname that is reported in protocol events from this cluster.

.PARAMETER protocol_auditing_enabled
	Specifies if logging for the I/O stream is enabled.

.PARAMETER syslog_log_time
	Specifies that events past a specified date are forwarded by the audit syslog forwarder. Format these events as follows: 'Topic@YYYY-MM-DD HH:MM:SS' format

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuditSettingsGlobalv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/audit/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuditSettingsGlobalv1
Set-Alias Set-isiAuditSettingsGlobal -Value Set-isiAuditSettingsGlobalv1
Export-ModuleMember -Alias Set-isiAuditSettingsGlobal

function Set-isiAuditSettingsv3{
<#
.SYNOPSIS
	Set Audit Settings

.DESCRIPTION
	Modify per-Access Zone Audit settings.

.PARAMETER audit_failure
	Filter of protocol operations to Audit when they fail.

.PARAMETER audit_success
	Filter of protocol operations to Audit when they succeed.

.PARAMETER syslog_audit_events
	Filter of Audit operations to forward to syslog.

.PARAMETER syslog_forwarding_enabled
	Enables forwarding of events to syslog.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Access zone which contains audit settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$audit_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$audit_success,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$syslog_audit_events,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$syslog_forwarding_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuditSettingsv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/audit/settings" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuditSettingsv3

function Set-isiAuditSettingsGlobal{
<#
.SYNOPSIS
	Set Audit Settings Global

.DESCRIPTION
	Modify Global Audit settings.

.PARAMETER audited_zones
	Specifies zones that are audited when the protocol_auditing_enabled property is enabled.

.PARAMETER cee_log_time
	Specifies that events past a certain date are forwarded by the audit CEE forwarder. Format these events as follows: 'Topic@YYYY-MM-DD HH:MM:SS'.

.PARAMETER cee_server_uris
	Specifies a list of Common Event Enabler (CEE) server URIs. Protocol audit logs are sent to these URIs for external processing.

.PARAMETER config_auditing_enabled
	Specifies whether logging for API configuration changes are enabled.

.PARAMETER config_syslog_enabled
	Specifies whether configuration audit syslog messages are forwarded.

.PARAMETER hostname
	Specifies the hostname that is reported in protocol events from this cluster.

.PARAMETER protocol_auditing_enabled
	Specifies if logging for the I/O stream is enabled.

.PARAMETER syslog_log_time
	Specifies that events past a specified date are forwarded by the audit syslog forwarder. Format these events as follows: 'Topic@YYYY-MM-DD HH:MM:SS' format

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuditSettingsGlobal')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/audit/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuditSettingsGlobal

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
	Specifies the system-provided ID for the audit topic.

.PARAMETER max_cached_messages
	Specifies the maximum number of messages that can be sent and received at the same time. Messages that are sent and received at the same time can be lost if a system crash occurs. You can prevent message loss by setting this property to 0, which sets audit logs to synchronous.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
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

.PARAMETER gid
	Specifies the numeric group identifier.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER provider
	Optional provider type.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthGroup')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/groups/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthGroup

function Set-isiAuthLogLevel{
<#
.SYNOPSIS
	Set Auth Log Level

.DESCRIPTION
	Set the current authentication service and netlogon logging level.

.PARAMETER level
	Valid auth logging levels
	Valid inputs: always,error,warning,info,verbose,debug,trace

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('always','error','warning','info','verbose','debug','trace')][string]$level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthLogLevel')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/auth/log-level" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthLogLevel

function Set-isiAuthMappingImport{
<#
.SYNOPSIS
	Set Auth Mapping Import

.DESCRIPTION
	Set or update a list of mappings between two personae.

.PARAMETER identities
	

.PARAMETER Force
	Force update of object without prompt

.PARAMETER replace
	Specify whether existing mappings should be replaced. The default behavior is to leave existing mappings intact and return an error.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$identities,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][object]$replace,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthMappingImport')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/auth/mapping/import" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthMappingImport

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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthMappingUsersRules

function Set-isiAuthProviderAdsv1{
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

.PARAMETER domain_controller
	Specifies the domain controller to which the authentication service should send requests

.PARAMETER domain_offline_alerts
	Sends an alert if the domain goes offline.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER ignored_trusted_domains
	Includes trusted domains when 'ignore_all_trusts' is set to false.

.PARAMETER ignore_all_trusts
	If set to true, ignores all trusted domains.

.PARAMETER include_trusted_domains
	Includes trusted domains when 'ignore_all_trusts' is set to true.

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

.PARAMETER node_dc_affinity
	Specifies the domain controller for which the node has affinity.

.PARAMETER node_dc_affinity_timeout
	Specifies the timeout for the domain controller for which the local node has affinity.

.PARAMETER nss_enumeration
	Enables the Active Directory provider to respond to 'getpwent' and 'getgrent' requests.

.PARAMETER reset_schannel
	Resets the secure channel to the primary domain.

.PARAMETER sfu_support
	Specifies whether to support RFC 2307 attributes on ADS domain controllers.
	Valid inputs: none,rfc2307

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allocate_gids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allocate_uids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$assume_default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$controller_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$domain_controller,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$domain_offline_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$ignored_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$ignore_all_trusts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$include_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$ldap_sign_and_seal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][array]$lookup_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$lookup_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$lookup_normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$lookup_normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$lookup_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$machine_password_changes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$machine_password_lifespan,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$node_dc_affinity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$node_dc_affinity_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$nss_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$reset_schannel,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][ValidateSet('none','rfc2307')][string]$sfu_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$store_sfu_mappings,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=29)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderAdsv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/ads/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderAdsv1
Set-Alias Set-isiAuthProviderAds -Value Set-isiAuthProviderAdsv1
Export-ModuleMember -Alias Set-isiAuthProviderAds

function Set-isiAuthProviderAdsv3{
<#
.SYNOPSIS
	Set Auth Provider Ads

.DESCRIPTION
	Modify the ADS provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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

.PARAMETER domain_controller
	Specifies the domain controller to which the authentication service should send requests

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

.PARAMETER instance
	Specifies Active Directory provider instnace.

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

.PARAMETER node_dc_affinity
	Specifies the domain controller for which the node has affinity.

.PARAMETER node_dc_affinity_timeout
	Specifies the timeout for the domain controller for which the local node has affinity.

.PARAMETER nss_enumeration
	Enables the Active Directory provider to respond to 'getpwent' and 'getgrent' requests.

.PARAMETER password
	Specifies the password used during domain join.

.PARAMETER reset_schannel
	Resets the secure channel to the primary domain.

.PARAMETER restrict_findable
	Check the provider for filtered lists of findable and unfindable users and groups.

.PARAMETER sfu_support
	Specifies whether to support RFC 2307 attributes on ADS domain controllers.
	Valid inputs: none,rfc2307

.PARAMETER spns
	Currently configured SPNs.

.PARAMETER store_sfu_mappings
	Stores SFU mappings permanently in the ID mapper.

.PARAMETER unfindable_groups
	Specifies groups that cannot be resolved by the provider.

.PARAMETER unfindable_users
	Specifies users that cannot be resolved by the provider.

.PARAMETER user
	Specifies the user name that has permission to join a machine to the given domain.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allocate_gids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allocate_uids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$assume_default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$check_online_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$controller_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$domain_controller,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$domain_offline_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$ignored_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$ignore_all_trusts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$include_trusted_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$instance,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$ldap_sign_and_seal,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$lookup_domains,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$lookup_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$lookup_normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$lookup_normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$lookup_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$machine_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$machine_password_changes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$machine_password_lifespan,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$node_dc_affinity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$node_dc_affinity_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$nss_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][bool]$reset_schannel,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateSet('none','rfc2307')][string]$sfu_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][array]$spns,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$store_sfu_mappings,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][string]$user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=39)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderAdsv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/auth/providers/ads/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderAdsv3

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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$create_home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enumerate_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$enumerate_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$findable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$findable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$group_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$group_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$home_directory_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][array]$listable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$listable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$login_shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$modifiable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$modifiable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$netgroup_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$password_file,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=33)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderFile')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/file/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderFile

function Set-isiAuthProviderKrb5v1{
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
	Specifies the key information for the Kerberos SPNs.

.PARAMETER keytab_file
	Specifies the path to a keytab file to import.

.PARAMETER manual_keying
	If true, keys are managed manually. If false, keys are managed through kadmin.

.PARAMETER new_name
	Specifies the Kerberos provider name.

.PARAMETER password
	Specifies the Kerberos provider password.

.PARAMETER realm
	Specifies the name of realm.

.PARAMETER status
	Specifies the status of the provider.

.PARAMETER user
	Specifies the name of the user that performs kadmin tasks.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderKrb5v1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/krb5/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderKrb5v1
Set-Alias Set-isiAuthProviderKrb5 -Value Set-isiAuthProviderKrb5v1
Export-ModuleMember -Alias Set-isiAuthProviderKrb5

function Set-isiAuthProviderKrb5v3{
<#
.SYNOPSIS
	Set Auth Provider Krb5

.DESCRIPTION
	Modify the KRB5 provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER keytab_entries
	Specifies the key information for the Kerberos SPNs.

.PARAMETER keytab_file
	Specifies the path to a keytab file to import.

.PARAMETER manual_keying
	If true, keys are managed manually. If false, keys are managed through kadmin.

.PARAMETER new_name
	Specifies the Kerberos provider name.

.PARAMETER password
	Specifies the Kerberos provider password.

.PARAMETER realm
	Specifies the name of realm.

.PARAMETER status
	Specifies the status of the provider.

.PARAMETER user
	Specifies the name of the user that performs kadmin tasks.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderKrb5v3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/auth/providers/krb5/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderKrb5v3

function Set-isiAuthProviderLdapv1{
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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$alternate_security_identities_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$bind_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('simple','gssapi','digest-md5')][string]$bind_mechanism,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$bind_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$bind_timeout,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$new_name,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=51)][array]$server_uris,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=63)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=64)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderLdapv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/ldap/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderLdapv1
Set-Alias Set-isiAuthProviderLdap -Value Set-isiAuthProviderLdapv1
Export-ModuleMember -Alias Set-isiAuthProviderLdap

function Set-isiAuthProviderLdapv3{
<#
.SYNOPSIS
	Set Auth Provider Ldap

.DESCRIPTION
	Modify the LDAP provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$alternate_security_identities_attribute,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$balance_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$base_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$bind_dn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('simple','gssapi','digest-md5')][string]$bind_mechanism,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$bind_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$bind_timeout,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$new_name,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=51)][array]$server_uris,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=63)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=64)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderLdapv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/auth/providers/ldap/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderLdapv3

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
	If true, enables authentication and identity management through the authentication provider.

.PARAMETER create_home_directory
	Automatically creates the home directory on the first login.

.PARAMETER home_directory_template
	Specifies the path to the home directory template.

.PARAMETER lockout_duration
	Specifies the length of time in seconds that an account will be inaccessible after multiple failed login attempts.

.PARAMETER lockout_threshold
	Specifies the number of failed login attempts necessary before an account is locked.

.PARAMETER lockout_window
	Specifies the duration of time in seconds in which the number of failed attempts set in the 'lockout_threshold' parameter must be made before an account is locked.

.PARAMETER login_shell
	Specifies the login shell path.

.PARAMETER machine_name
	Specifies the domain for this provider through which users and groups are qualified.

.PARAMETER max_password_age
	Specifies the maximum password age in seconds.

.PARAMETER min_password_age
	Specifies the minimum password age in seconds.

.PARAMETER min_password_length
	Specifies the minimum password length.

.PARAMETER new_name
	Specifies the local provider name.

.PARAMETER password_complexity
	Specifies the conditions required for a password.

.PARAMETER password_history_length
	Specifies the number of previous passwords to store.

.PARAMETER password_prompt_time
	Specifies the time in seconds remaining before a user will be prompted for a password change.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderLocal

function Set-isiAuthProviderNisv1{
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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$balance_servers,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$nis_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$request_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$retry_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][bool]$ypmatch_using_tcp,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=33)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderNisv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/providers/nis/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderNisv1
Set-Alias Set-isiAuthProviderNis -Value Set-isiAuthProviderNisv1
Export-ModuleMember -Alias Set-isiAuthProviderNis

function Set-isiAuthProviderNisv3{
<#
.SYNOPSIS
	Set Auth Provider Nis

.DESCRIPTION
	Modify the NIS provider.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$balance_servers,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$nis_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$normalize_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$normalize_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][ValidateSet('all','v2only','none')][string]$ntlm_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$provider_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$request_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$restrict_findable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_listable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$retry_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][array]$servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$unfindable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$unfindable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][array]$unlistable_groups,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][array]$unlistable_users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$user_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][bool]$ypmatch_using_tcp,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=33)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthProviderNisv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/auth/providers/nis/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthProviderNisv3

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
	Specifies the description of the role.

.PARAMETER members
	Specifies the users or groups that have this role.

.PARAMETER new_name
	Specifies the name of the role.

.PARAMETER privileges
	Specifies the privileges granted by this role.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthRole

function Set-isiAuthSettingsAcls{
<#
.SYNOPSIS
	Set Auth Settings Acls

.DESCRIPTION
	Modify cluster ACL policy settings.

.PARAMETER access
	Access checks (chmod, chown).
	Valid inputs: unix,windows

.PARAMETER calcmode
	Displayed mode bits.
	Valid inputs: approx,777

.PARAMETER calcmode_group
	Approximate group mode bits when ACL exists.
	Valid inputs: group_aces,group_only

.PARAMETER calcmode_owner
	Approximate owner mode bits when ACL exists.
	Valid inputs: owner_aces,owner_only

.PARAMETER chmod
	chmod on files with existing ACLs.
	Valid inputs: remove,replace,replace_users_and_groups,merge,deny,ignore

.PARAMETER chmod_007
	chmod (007) on files with existing ACLs.
	Valid inputs: default,remove

.PARAMETER chmod_inheritable
	ACLs created on directories by UNIX chmod.
	Valid inputs: yes,no

.PARAMETER chown
	chown/chgrp on files with existing ACLs.
	Valid inputs: owner_group_and_acl,owner_group_only,ignore

.PARAMETER create_over_smb
	ACL creation over SMB.
	Valid inputs: allow,disallow

.PARAMETER dos_attr
	 Read only DOS attribute.
	Valid inputs: deny_smb,deny_smb_and_nfs

.PARAMETER group_owner_inheritance
	Group owner inheritance.
	Valid inputs: native,parent,creator

.PARAMETER rwx
	Treatment of 'rwx' permissions.
	Valid inputs: retain,full_control

.PARAMETER synthetic_denies
	Synthetic 'deny' ACEs.
	Valid inputs: none,remove

.PARAMETER utimes
	Access check (utimes)
	Valid inputs: only_owner,owner_and_write

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('unix','windows')][string]$access,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('approx','777')][string]$calcmode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('group_aces','group_only')][string]$calcmode_group,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('owner_aces','owner_only')][string]$calcmode_owner,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('remove','replace','replace_users_and_groups','merge','deny','ignore')][string]$chmod,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('default','remove')][string]$chmod_007,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('yes','no')][string]$chmod_inheritable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('owner_group_and_acl','owner_group_only','ignore')][string]$chown,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('allow','disallow')][string]$create_over_smb,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('deny_smb','deny_smb_and_nfs')][string]$dos_attr,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateSet('native','parent','creator')][string]$group_owner_inheritance,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateSet('retain','full_control')][string]$rwx,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateSet('none','remove')][string]$synthetic_denies,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateSet('only_owner','owner_and_write')][string]$utimes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=14)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$queryArguments = @()
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsAcls')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/auth/settings/acls" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthSettingsAcls

function Set-isiAuthSettingsGlobal{
<#
.SYNOPSIS
	Set Auth Settings Global

.DESCRIPTION
	Modify the global settings.

.PARAMETER alloc_retries
	Specifies the number of times to retry an ID allocation before failing.

.PARAMETER gid_range_enabled
	If true, allocates GIDs from a fixed range.

.PARAMETER gid_range_max
	Specifies the ending number for a fixed range from which GIDs are allocated.

.PARAMETER gid_range_min
	Specifies the starting number for a fixed range from which GIDs are allocated.

.PARAMETER gid_range_next
	Specifies the next GID to allocate.

.PARAMETER group_uid
	Specifies the user iD for a group when requested by the kernel.

.PARAMETER load_providers
	Specifies which providers are loaded by the authentication daemon (lsassd).

.PARAMETER min_mapped_rid
	Starts the RID in the local domain to map a UID and a GID.

.PARAMETER null_gid
	Specifies an alternative GID when the kernel is unable to retrieve a GID for a persona.

.PARAMETER null_uid
	Specifies an alternative UID when the kernel is unable to retrieve a UID for a persona.

.PARAMETER on_disk_identity
	Specifies the type of identity that is stored on disk.
	Valid inputs: native,unix,sid

.PARAMETER rpc_block_time
	Specifies the minimum amount of time in milliseconds to wait before performing an oprestart.

.PARAMETER rpc_max_requests
	Specifies the maximum number of outstanding RPC requests.

.PARAMETER rpc_timeout
	Specifies the maximum amount of time in seconds to wait for an idmap response.

.PARAMETER send_ntlmv2
	If true, sends NTLMv2 responses.

.PARAMETER space_replacement
	Specifies the space replacement character.

.PARAMETER system_gid_threshold
	Specifies the minimum GID to attempt to look up in the idmap database.

.PARAMETER system_uid_threshold
	Specifies the minimum UID to attempt to look up in the idmap database.

.PARAMETER uid_range_enabled
	If true, allocates UIDs from a fixed range.

.PARAMETER uid_range_max
	Specifies the ending number for a fixed range from which UIDs are allocated.

.PARAMETER uid_range_min
	Specifies the starting number for a fixed range from which UIDs are allocated.

.PARAMETER uid_range_next
	Specifies the next UID to allocate.

.PARAMETER unknown_gid
	Specifies the GID for the unknown (anonymous) group.

.PARAMETER unknown_uid
	Specifies the UID for the unknown (anonymous) user.

.PARAMETER user_object_cache_size
	Specifies the maximum size (in bytes) of the security object cache in the authentication daemon.

.PARAMETER workgroup
	Specifies the NetBIOS workgroup or domain.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Zone which contains any per-zone settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$alloc_retries,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$gid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$gid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$gid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$gid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$group_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][array]$load_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$min_mapped_rid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$null_gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$null_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateSet('native','unix','sid')][string]$on_disk_identity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$rpc_block_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$rpc_max_requests,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][int]$rpc_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$send_ntlmv2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$space_replacement,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$system_gid_threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$system_uid_threshold,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$uid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$uid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$uid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$uid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$unknown_gid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$unknown_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$user_object_cache_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][string]$workgroup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=26)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsGlobal')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/settings/global" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
	If true, always attempts to preauthenticate to the domain controller.

.PARAMETER default_realm
	Specifies the realm for unqualified names.

.PARAMETER dns_lookup_kdc
	If true, find KDCs through the DNS.

.PARAMETER dns_lookup_realm
	If true, find realm names through the DNS.

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
			return $ISIObject
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

.PARAMETER realm
	Specifies the name of the realm.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsKrb5Domain')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/settings/krb5/domains/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
	Specifies the administrative server hostname.

.PARAMETER default_domain
	Specifies the default domain mapped to the realm.

.PARAMETER is_default_realm
	If true, indicates that the realm is the default.

.PARAMETER kdc
	Specifies the list of KDC hostnames.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$admin_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$default_domain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$is_default_realm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$kdc,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsKrb5Realm')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/auth/settings/krb5/realms/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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

.PARAMETER cache_entry_expiry
	Specifies the cache expiry in seconds of the idmapper.

.PARAMETER gid_range_enabled
	If true, allocates GIDs from a fixed range.

.PARAMETER gid_range_max
	Specifies the ending number for a fixed range from which GIDs are allocated.

.PARAMETER gid_range_min
	Specifies the starting number for a fixed range from which GIDs are allocated.

.PARAMETER gid_range_next
	Specifies the next GID to allocate.

.PARAMETER uid_range_enabled
	If true, allocates UIDs from a fixed range.

.PARAMETER uid_range_max
	Specifies the ending number for a fixed range from which UIDs are allocated.

.PARAMETER uid_range_min
	Specifies the starting number for a fixed range from which UIDs are allocated.

.PARAMETER uid_range_next
	Specifies the next UID to allocate.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Access zone which contains mapping settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$gid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$gid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$gid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$gid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$uid_range_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$uid_range_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$uid_range_min,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$uid_range_next,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthSettingsMapping')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/settings/mapping" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER provider
	Optional provider type.

.PARAMETER access_zone
	Optional zone.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$gecos,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$home_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$password_expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$primary_group,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$prompt_password_change,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$shell,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$sid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$unlock,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=14)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateNotNullOrEmpty()][string]$provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthUser')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/users/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthUser

function Set-isiAuthUserChangePasswordv3{
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

.PARAMETER access_zone
	Specifies access zone containing user.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_password,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$old_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthUserChangePasswordv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/auth/users/$parameter1/change-password" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthUserChangePasswordv3

function Set-isiAuthUserChangePasswordv1{
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

.PARAMETER access_zone
	Specifies access zone containing user.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_password,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$old_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiAuthUserChangePasswordv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/auth/users/$parameter1/change_password" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiAuthUserChangePasswordv1

function Set-isiCloudAccountv3{
<#
.SYNOPSIS
	Set Cloud Account

.DESCRIPTION
	Modify cloud account.  All fields are optional, but one or more must be supplied.

.PARAMETER id
	Account id

.PARAMETER name
	Account name

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

.PARAMETER new_name
	A unique name for this account

.PARAMETER skip_ssl_validation
	Indicates whether to skip SSL certificate validation when connecting to the cloud

.PARAMETER storage_region
	(S3 only) An appropriate region for the S3 account.  For example, faster access times may be gained by referencing a nearby region

.PARAMETER telemetry_bucket
	(S3 only) The name of the bucket into which generated metrics reports are placed by the cloud service provider

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$account_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$account_username,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$birth_cluster_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$skip_ssl_validation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$storage_region,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$telemetry_bucket,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$uri,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=11)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudAccountv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cloud/accounts/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudAccountv3

function Set-isiCloudJobv3{
<#
.SYNOPSIS
	Set Cloud Job

.DESCRIPTION
	Modify a cloud job or operation.

.PARAMETER id
	Job id

.PARAMETER name
	Job name

.PARAMETER all
	Whether to apply to the given operation type or to all jobs of the given operation type

.PARAMETER state
	The desired state of the job or operation
	Valid inputs: resume,pause,cancel

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('resume','pause','cancel')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudJobv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/cloud/jobs/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudJobv3

function Set-isiCloudPoolv3{
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
	A list of valid names for the accounts in this pool.  There is currently only one account allowed per pool.

.PARAMETER birth_cluster_id
	The guid of the cluster where this pool was created

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$accounts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$birth_cluster_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$vendor,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudPoolv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cloud/pools/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudPoolv3

function Set-isiCloudSettingsv3{
<#
.SYNOPSIS
	Set Cloud Settings

.DESCRIPTION
	Modify one or more settings.

.PARAMETER cloud_policy_defaults
	The default filepool policy values for cloud pools.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][object]$cloud_policy_defaults,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$retry_coefficient_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$retry_coefficient_cache_invalidation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$retry_coefficient_cloud_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$retry_coefficient_local_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$retry_coefficient_read_ahead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$retry_coefficient_recall,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$retry_coefficient_writeback,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$sleep_timeout_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][object]$sleep_timeout_cache_invalidation,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$sleep_timeout_cloud_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][object]$sleep_timeout_local_garbage_collection,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$sleep_timeout_read_ahead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][object]$sleep_timeout_recall,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][object]$sleep_timeout_writeback,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=15)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiCloudSettingsv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cloud/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiCloudSettingsv3

function Set-isiClusterEmail{
<#
.SYNOPSIS
	Set Cluster Email

.DESCRIPTION
	Modify the cluster email notification settings.  All input fields are optional, but one or more must be supplied.

.PARAMETER batch_mode
	This setting determines how notifications will be batched together to be sent by email.  'none' means each notification will be sent separately.  'severity' means notifications of the same severity will be sent together.  'category' means notifications of the same category will be sent together.  'all' means all notifications will be batched together and sent in a single email.
	Valid inputs: all,severity,category,none

.PARAMETER mail_relay
	The address of the SMTP server to be used for relaying the notification messages.  An SMTP server is required in order to send notifications.  If this string is empty, no emails will be sent.

.PARAMETER mail_sender
	The full email address that will appear as the sender of notification messages.

.PARAMETER mail_subject
	The subject line for notification messages from this cluster.

.PARAMETER smtp_auth_passwd
	Password to authenticate with if SMTP authentication is being used.

.PARAMETER smtp_auth_security
	The type of secure communication protocol to use if SMTP is being used.  If 'none', plain text will be used, if 'starttls', the encrypted STARTTLS protocol will be used.
	Valid inputs: none,starttls

.PARAMETER smtp_auth_username
	Username to authenticate with if SMTP authentication is being used.

.PARAMETER smtp_port
	The port on the SMTP server to be used for relaying the notification messages.  

.PARAMETER user_template
	Location of a custom template file that can be used to specify the layout of the notification emails.

.PARAMETER use_smtp_auth
	If true, this cluster will send SMTP authentication credentials to the SMTP relay server in order to send its notification emails.  If false, the cluster will attempt to send its notification emails without authentication.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('all','severity','category','none')][string]$batch_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$mail_relay,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$mail_sender,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$mail_subject,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$smtp_auth_passwd,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('none','starttls')][string]$smtp_auth_security,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$smtp_auth_username,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$smtp_port,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$user_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$use_smtp_auth,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=10)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterEmail')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/cluster/email" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterEmail

function Set-isiClusterIdentityv3{
<#
.SYNOPSIS
	Set Cluster Identity

.DESCRIPTION
	Modify the login information.

.PARAMETER description
	A description of the cluster.

.PARAMETER logon
	The information displayed when a user logs in to the cluster.

.PARAMETER name
	The name of the cluster.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$logon,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterIdentityv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/identity" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterIdentityv3

function Set-isiClusterNode{
<#
.SYNOPSIS
	Set Cluster Node

.DESCRIPTION
	Modify one or more node settings.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER drives
	List of the drives in this node.

.PARAMETER state
	Node state information (reported and modifiable).

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$drives,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][object]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterNode')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/nodes/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterNode

function Set-isiClusterNodeStateReadonly{
<#
.SYNOPSIS
	Set Cluster Node State Readonly

.DESCRIPTION
	Modify one or more node readonly state settings.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER allowed
	The current read-only mode allowed status for the node.

.PARAMETER enabled
	The current read-only user mode status for the node. NOTE: If read-only mode is currently disallowed for this node, it will remain read/write until read-only mode is allowed again. This value only sets or clears any user-specified requests for read-only mode. If the node has been placed into read-only mode by the system, it will remain in read-only mode until the system conditions which triggered read-only mode have cleared.

.PARAMETER mode
	The current read-only mode status for the node.

.PARAMETER status
	The current read-only mode status description for the node.

.PARAMETER valid
	The read-only state values are valid (False = Error).

.PARAMETER value
	The current read-only value (enumerated bitfield) for the node.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allowed,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$status,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$valid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$value,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterNodeStateReadonly')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/nodes/$parameter1/state/readonly" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterNodeStateReadonly

function Set-isiClusterNodeStateServicelight{
<#
.SYNOPSIS
	Set Cluster Node State Servicelight

.DESCRIPTION
	Modify one or more node service light state settings.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER enabled
	The node service light state (True = on).

.PARAMETER present
	This node has a service light.

.PARAMETER supported
	This node supports a service light.

.PARAMETER valid
	The node service light state is valid (False = Error).

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$present,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$supported,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$valid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterNodeStateServicelight')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/nodes/$parameter1/state/servicelight" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterNodeStateServicelight

function Set-isiClusterNodeStateSmartfail{
<#
.SYNOPSIS
	Set Cluster Node State Smartfail

.DESCRIPTION
	Modify smartfail state of the node.  Only the 'smartfailed' body member has any effect on node smartfail state.

.PARAMETER id
	Lnn id

.PARAMETER name
	Lnn name

.PARAMETER dead
	This node is dead (dead_devs).

.PARAMETER down
	This node is down (down_devs).

.PARAMETER in_cluster
	This node is in the cluster (all_devs).

.PARAMETER readonly
	This node is readonly (ro_devs).

.PARAMETER shutdown_readonly
	This node is shutdown readonly (down_devs).

.PARAMETER smartfailed
	This node is smartfailed (soft_devs).

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$dead,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$down,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$in_cluster,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$shutdown_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$smartfailed,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterNodeStateSmartfail')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/nodes/$parameter1/state/smartfail" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterNodeStateSmartfail

function Set-isiClusterOwner{
<#
.SYNOPSIS
	Set Cluster Owner

.DESCRIPTION
	Modify the cluster contact info settings.  All input fields are optional, but one or more must be supplied.

.PARAMETER company
	Cluster owner company name.

.PARAMETER location
	Cluster owner location.

.PARAMETER primary_email
	Cluster owner primary email address.

.PARAMETER primary_name
	Cluster owner primary contact name.

.PARAMETER primary_phone1
	Cluster owner primary contact phone number 1.

.PARAMETER primary_phone2
	Cluster owner primary contact phone number 2.

.PARAMETER secondary_email
	Cluster owner secondary email address.

.PARAMETER secondary_name
	Cluster owner secondary contact name.

.PARAMETER secondary_phone1
	Cluster owner secondary contact phone number 1.

.PARAMETER secondary_phone2
	Cluster owner secondary contact phone number 2.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$company,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$location,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$primary_email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$primary_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$primary_phone1,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$primary_phone2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$secondary_email,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$secondary_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$secondary_phone1,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$secondary_phone2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=10)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterOwner')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/cluster/owner" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterOwner

function Set-isiClusterTimev3{
<#
.SYNOPSIS
	Set Cluster Time

.DESCRIPTION
	Set cluster time.  Time will mostly be synchronized across nodes, but there may be slight drift.

.PARAMETER time
	The current time on the cluster as a UNIX epoch (seconds since 1/1/1970), as reported by this node.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterTimev3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/time" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterTimev3

function Set-isiClusterTimezone{
<#
.SYNOPSIS
	Set Cluster Timezone

.DESCRIPTION
	Set a new timezone for the cluster.

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterTimezone')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/timezone" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterTimezone

function Set-isiClusterTimezoneSettings{
<#
.SYNOPSIS
	Set Cluster Timezone Settings

.DESCRIPTION
	Modify the cluster timezone.

.PARAMETER abbreviation
	The abbreviation for this timezone.

.PARAMETER path
	The timezone path.  This is the unique identifier for the timezone.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$abbreviation,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiClusterTimezoneSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/cluster/timezone/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiClusterTimezoneSettings

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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiDedupeSettings

function Set-isiEventAlertCondition{
<#
.SYNOPSIS
	Set Event Alert Condition

.DESCRIPTION
	Modify the alert-condition

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER categories
	Event Group categories to be alerted

.PARAMETER channel_ids
	Channels for alert

.PARAMETER condition
	Trigger condition for alert
	Valid inputs: NEW,NEW EVENTS,ONGOING,SEVERITY INCREASE,SEVERITY DECREASE,RESOLVED

.PARAMETER eventgroup_ids
	Event Group IDs to be alerted

.PARAMETER interval
	Required with ONGOING condition only, period in seconds between alerts of ongoing conditions

.PARAMETER limit
	Required with NEW EVENTS condition only, limits the number of alerts sent as events are added

.PARAMETER transient
	Any eventgroup lasting less than this many seconds is deemed transient and will not generate alerts under this condition.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$categories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$channel_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('NEW','NEW EVENTS','ONGOING','SEVERITY INCREASE','SEVERITY DECREASE','RESOLVED')][string]$condition,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$eventgroup_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$transient,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiEventAlertCondition')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/event/alert-conditions/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiEventAlertCondition

function Set-isiEventChannel{
<#
.SYNOPSIS
	Set Event Channel

.DESCRIPTION
	Modify the alert-condition

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER allowed_nodes
	Nodes that can be masters for this channel

.PARAMETER enabled
	Channel is to be used or not

.PARAMETER excluded_nodes
	Nodes that can be masters for this channel

.PARAMETER parameters
	A collection of parameters dependent on the channel type

.PARAMETER system
	Channel is a pre-defined system channel

.PARAMETER type
	The mechanism used by the channel
	Valid inputs: connectemc,smtp,snmp

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$allowed_nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$excluded_nodes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][object]$parameters,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$system,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('connectemc','smtp','snmp')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiEventChannel')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/event/channels/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiEventChannel

function Set-isiEventEventgroupOccurrences{
<#
.SYNOPSIS
	Set Event Eventgroup Occurrences

.DESCRIPTION
	Modify all eventgroup occurrences, resolve or ignore all

.PARAMETER ignore
	True if eventgroup is to be ignored

.PARAMETER resolved
	True if eventgroup is to be resolved

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$ignore,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$resolved,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiEventEventgroupOccurrences')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/event/eventgroup-occurrences" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiEventEventgroupOccurrences

function Set-isiEventEventgroupOccurrence{
<#
.SYNOPSIS
	Set Event Eventgroup Occurrence

.DESCRIPTION
	modify eventgroup occurrence.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER ignore
	True if eventgroup is to be ignored

.PARAMETER resolved
	True if eventgroup is to be resolved

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$ignore,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$resolved,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiEventEventgroupOccurrence')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/event/eventgroup-occurrences/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiEventEventgroupOccurrence

function Set-isiEventSettings{
<#
.SYNOPSIS
	Set Event Settings

.DESCRIPTION
	Update settings

.PARAMETER heartbeat_interval
	Interval between heartbeat events. "daily", "weekly", or "monthly".

.PARAMETER maintenance
	Maintenance period

.PARAMETER retention_days
	Retention period in days

.PARAMETER storage_limit
	Storage limit in megabytes per terabyte of available storage

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$heartbeat_interval,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$maintenance,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$retention_days,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$storage_limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiEventSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/event/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiEventSettings

function Set-isiFileFilterSettings{
<#
.SYNOPSIS
	Set File Filter Settings

.DESCRIPTION
	Modify one or more File Filtering settings for an access zone

.PARAMETER file_filtering_enabled
	Indicates whether file filtering is enabled on this zone.

.PARAMETER file_filter_extensions
	List of file extensions to be filtered.

.PARAMETER file_filter_type
	Specifies if filter list is for deny or allow. Default is deny.
	Valid inputs: deny,allow

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$file_filtering_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$file_filter_extensions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('deny','allow')][string]$file_filter_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFileFilterSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/file-filter/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFileFilterSettings

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
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
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
			return $ISIObject
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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFilesystemCharacterEncoding

function Set-isiFsaResultv1{
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFsaResultv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/fsa/results/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFsaResultv1
Set-Alias Set-isiFsaResult -Value Set-isiFsaResultv1
Export-ModuleMember -Alias Set-isiFsaResult

function Set-isiFsaResultv3{
<#
.SYNOPSIS
	Set Fsa Result

.DESCRIPTION
	Modify result set. Only the pinned property can be changed at this time.

.PARAMETER id
	Id id

.PARAMETER name
	Id name

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$pinned,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFsaResultv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/fsa/results/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFsaResultv3

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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFsaSettings

function Set-isiHardwareFcport{
<#
.SYNOPSIS
	Set Hardware Fcport

.DESCRIPTION
	Change wwnn, wwpn, state, topology, or rate of a FC port

.PARAMETER id
	Port id

.PARAMETER name
	Port name

.PARAMETER new_id
	The unique display id

.PARAMETER rate
	
	Valid inputs: auto,1,2,4,8

.PARAMETER state
	State of the port
	Valid inputs: enable,disable

.PARAMETER topology
	
	Valid inputs: auto,ptp,loop

.PARAMETER wwnn
	World wide node name of the port

.PARAMETER wwpn
	World wide port name of the port

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('auto','1','2','4','8')][string]$rate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('enable','disable')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('auto','ptp','loop')][string]$topology,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$wwnn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$wwpn,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_id){
				$BoundParameters.Remove('new_id') | out-null
				$BoundParameters.Add('id',$new_id)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHardwareFcport')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/hardware/fcports/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHardwareFcport

function Set-isiHardwareTape{
<#
.SYNOPSIS
	Set Hardware Tape

.DESCRIPTION
	Tape/Changer device modify

.PARAMETER id
	Name id

.PARAMETER name
	Name name

.PARAMETER new_name
	The name of the device

.PARAMETER state
	Set the device state to close
	Valid inputs: closed

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('closed')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHardwareTape')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/hardware/tape/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHardwareTape

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
	Valid inputs: run,pause,cancel

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('run','pause','cancel')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiJob')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/job/jobs/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiJobPolicy')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/job/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiJobType')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/job/types/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiJobType

function Set-isiNetworkDnscache{
<#
.SYNOPSIS
	Set Network Dnscache

.DESCRIPTION
	Modify network dns cache settings.

.PARAMETER cache_entry_limit
	DNS cache entry limit

.PARAMETER cluster_timeout
	Timeout value for calls made to other nodes in the cluster

.PARAMETER dns_timeout
	Timeout value for calls made to the dns resolvers

.PARAMETER eager_refresh
	Lead time to refresh cache entries nearing expiration

.PARAMETER testping_delta
	Deltas for checking cbind cluster health

.PARAMETER ttl_max_noerror
	Upper bound on ttl for cache hits

.PARAMETER ttl_max_nxdomain
	Upper bound on ttl for nxdomain

.PARAMETER ttl_max_other
	Upper bound on ttl for non-nxdomain failures

.PARAMETER ttl_max_servfail
	Upper bound on ttl for server failures

.PARAMETER ttl_min_noerror
	Lower bound on ttl for cache hits

.PARAMETER ttl_min_nxdomain
	Lower bound on ttl for nxdomain

.PARAMETER ttl_min_other
	Lower bound on ttl for non-nxdomain failures

.PARAMETER ttl_min_servfail
	Lower bound on ttl for server failures

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$cache_entry_limit,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$cluster_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$dns_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$eager_refresh,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$testping_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$ttl_max_noerror,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$ttl_max_nxdomain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$ttl_max_other,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$ttl_max_servfail,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$ttl_min_noerror,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$ttl_min_nxdomain,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$ttl_min_other,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$ttl_min_servfail,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=13)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNetworkDnscache')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/network/dnscache" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNetworkDnscache

function Set-isiNetworkExternal{
<#
.SYNOPSIS
	Set Network External

.DESCRIPTION
	Modify external network settings.

.PARAMETER sbr
	Enable or disable Source Based Routing (Defaults to false)

.PARAMETER sc_rebalance_delay
	Delay in seconds for IP rebalance.

.PARAMETER tcp_ports
	List of client TCP ports.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$sbr,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$sc_rebalance_delay,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$tcp_ports,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNetworkExternal')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/network/external" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNetworkExternal

function Set-isiNetworkGroupnet{
<#
.SYNOPSIS
	Set Network Groupnet

.DESCRIPTION
	Modify a network groupnet.

.PARAMETER id
	Groupnet id

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$dns_cache_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$dns_options,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$dns_search,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][array]$dns_servers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$server_side_dns_search,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$parameter1 = $id
			$BoundParameters.Remove('id') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNetworkGroupnet')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/network/groupnets/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNetworkGroupnet

function Set-isiNetworkGroupnetSubnet{
<#
.SYNOPSIS
	Set Network Groupnet Subnet

.DESCRIPTION
	Modify a network subnet.

.PARAMETER groupnet_id
	Groupnet groupnet_id

.PARAMETER groupnet_name
	Groupnet groupnet_name

.PARAMETER id
	 id

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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$groupnet_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$groupnet_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$dsr_addrs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$gateway,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$gateway_priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$mtu,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$prefixlen,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$sc_service_addr,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$vlan_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$vlan_id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=12)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNetworkGroupnetSubnet')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/network/groupnets/$parameter1/subnets/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNetworkGroupnetSubnet

function Set-isiFtpSettings{
<#
.SYNOPSIS
	Set Protocols Ftp Settings

.DESCRIPTION
	Modify the FTP settings. All input fields are optional, but one or more must be supplied.

.PARAMETER accept_timeout
	The timeout, in seconds, for a remote client to establish a PASV style data connection.

.PARAMETER allow_anon_access
	Controls whether anonymous logins are permitted or not.

.PARAMETER allow_anon_upload
	Controls whether anonymous users will be permitted to upload files.

.PARAMETER allow_dirlists
	If set to false, all directory list commands will return a permission denied error.

.PARAMETER allow_downloads
	If set to false, all downloads requests will return a permission denied error.

.PARAMETER allow_local_access
	Controls whether local logins are permitted or not.

.PARAMETER allow_writes
	This controls whether any FTP commands which change the filesystem are allowed or not.

.PARAMETER always_chdir_homedir
	This controls whether FTP will always initially change directories to the home directory of the user, regardless of whether it is chroot-ing.

.PARAMETER anon_chown_username
	This is the name of the user who is given ownership of anonymously uploaded files.

.PARAMETER anon_password_list
	A list of passwords for anonymous users.

.PARAMETER anon_root_path
	This option represents a directory in /ifs which vsftpd will try to change into after an anonymous login.

.PARAMETER anon_umask
	The value that the umask for file creation is set to for anonymous users.

.PARAMETER ascii_mode
	Controls whether ascii mode data transfers are honored for various types of requests.
	Valid inputs: off,upload,download,both

.PARAMETER chroot_exception_list
	A list of users that are not chrooted when logging in.

.PARAMETER chroot_local_mode
	If set to 'all', all local users will be (by default) placed in a chroot() jail in their home directory after login. If set to 'all-with-exceptions', all local users except those listed in the chroot exception list (isi ftp chroot-exception-list) will be placed in a chroot() jail in their home directory after login. If set to 'none', no local users will be chrooted by default. If set to 'none-with-exceptions', only the local users listed in the chroot exception list (isi ftp chroot-exception-list) will be place in a chroot() jail in their home directory after login.
	Valid inputs: all,none,all-with-exceptions,none-with-exceptions

.PARAMETER connect_timeout
	The timeout, in seconds, for a remote client to respond to our PORT style data connection.

.PARAMETER data_timeout
	The timeout, in seconds, which is roughly the maximum time we permit data transfers to stall for with no progress. If the timeout triggers, the remote client is kicked off.

.PARAMETER denied_user_list
	A list of uses that will be denied access.

.PARAMETER dirlist_localtime
	If enabled, display directory listings with the time in your local time zone. The default is to display GMT. The times returned by the MDTM FTP command are also affected by this option.

.PARAMETER dirlist_names
	When set to 'hide',  all user and group information in directory listings will be displayed as 'ftp'. When set to 'textual', textual names are shown in the user and group fields of directory listings. When set to 'numeric', numeric IDs are show in the user and group fields of directory listings.
	Valid inputs: numeric,textual,hide

.PARAMETER file_create_perm
	The permissions with which uploaded files are created. Umasks are applied on top of this value.

.PARAMETER limit_anon_passwords
	This field determines whether the anon_password_list is used.

.PARAMETER local_root_path
	This option represents a directory in /ifs which vsftpd will try to change into after a local login.

.PARAMETER local_umask
	The value that the umask for file creation is set to for local users.

.PARAMETER server_to_server
	If enabled, allow server-to-server (FXP) transfers.

.PARAMETER service
	This field controls whether the FTP daemon is running.

.PARAMETER session_support
	If enabled, maintain login sessions for each user through Pluggable Authentication Modules (PAM). Disabling this option prevents the ability to do automatic home directory creation if that functionality were otherwise available.

.PARAMETER session_timeout
	The timeout, in seconds, which is roughly the maximum time we permit data transfers to stall for with no progress. If the timeout triggers, the remote client is kicked off.

.PARAMETER user_config_dir
	Specifies the directory where per-user config overrides can be found.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$accept_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$allow_anon_access,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allow_anon_upload,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_dirlists,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_downloads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$allow_local_access,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$allow_writes,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$always_chdir_homedir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$anon_chown_username,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][array]$anon_password_list,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$anon_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$anon_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateSet('off','upload','download','both')][string]$ascii_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][array]$chroot_exception_list,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateSet('all','none','all-with-exceptions','none-with-exceptions')][string]$chroot_local_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$connect_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$data_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$denied_user_list,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$dirlist_localtime,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][ValidateSet('numeric','textual','hide')][string]$dirlist_names,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$file_create_perm,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$limit_anon_passwords,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][string]$local_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$local_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$server_to_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$session_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][int]$session_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$user_config_dir,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=29)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiFtpSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ftp/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiFtpSettings

function Set-isiHdfsLogLevel{
<#
.SYNOPSIS
	Set Protocols Hdfs Log Level

.DESCRIPTION
	Modify the HDFS service log-level.

.PARAMETER level
	Setup the HDFS service log level for this node
	Valid inputs: always,error,warning,info,verbose,debug,trace,default

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('always','error','warning','info','verbose','debug','trace','default')][string]$level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsLogLevel')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/hdfs/log-level" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsLogLevel

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsProxyUser')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$proxyuser_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$proxyuser_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter2 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsProxyUserMember')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/hdfs/proxyusers/$parameter1/members/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsRack

function Set-isiHdfsSettingsv3{
<#
.SYNOPSIS
	Set Protocols Hdfs Settings

.DESCRIPTION
	Modify HDFS properties.

.PARAMETER ambari_namenode
	NameNode of Ambari server

.PARAMETER ambari_server
	Ambari server

.PARAMETER authentication_mode
	Type of authentication for HDFS protocol.
	Valid inputs: all,simple_only,kerberos_only

.PARAMETER default_block_size
	Block size (size=2**value) reported by HDFS server.

.PARAMETER default_checksum_type
	Checksum type reported by HDFS server.
	Valid inputs: none,crc32,crc32c

.PARAMETER odp_version
	ODP stack repository version number

.PARAMETER root_directory
	HDFS root directory

.PARAMETER service
	Enable or disable the HDFS service.

.PARAMETER webhdfs_enabled
	Enable or disable WebHDFS

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$ambari_namenode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$ambari_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('all','simple_only','kerberos_only')][string]$authentication_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$default_block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('none','crc32','crc32c')][string]$default_checksum_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$odp_version,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$root_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$webhdfs_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHdfsSettingsv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/hdfs/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHdfsSettingsv3

function Set-isiHttpSettings{
<#
.SYNOPSIS
	Set Protocols Http Settings

.DESCRIPTION
	Modify HTTP properties.

.PARAMETER access_control
	Enable Access Control Authentication

.PARAMETER basic_authentication
	Enable Basic Authentication

.PARAMETER dav
	Enable DAV specification

.PARAMETER enable_access_log
	Enable HTTP access logging

.PARAMETER integrated_authentication
	Enable Integrated Authentication

.PARAMETER server_root
	Document root directory. Must be within /ifs.

.PARAMETER service
	Enable/disable the HTTP service or redirect to WebUI.
	Valid inputs: enabled,disabled,redirect

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$access_control,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$basic_authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$dav,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$enable_access_log,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$integrated_authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$server_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('enabled','disabled','redirect')][string]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiHttpSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/http/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiHttpSettings

function Set-isiNdmpDiagnostics{
<#
.SYNOPSIS
	Set Protocols Ndmp Diagnostics

.DESCRIPTION
	Modify ndmp diagnostics settings.

.PARAMETER diag_level
	Diagnostics level for ndmp.

.PARAMETER protocol_version
	The version of the ndmp protocol.

.PARAMETER trace_level
	Trace level for ndmp.
	Valid inputs: none,standard,include-file-history,log-file-history

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$diag_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$protocol_version,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('none','standard','include-file-history','log-file-history')][string]$trace_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNdmpDiagnostics')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ndmp/diagnostics" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNdmpDiagnostics

function Set-isiNdmpSettingsGlobal{
<#
.SYNOPSIS
	Set Protocols Ndmp Settings Global

.DESCRIPTION
	Modify one or more settings.

.PARAMETER bre_max_num_contexts
	Maximum number of BRE contexts.

.PARAMETER dma
	A unique identifier for the dma vendor.
	Valid inputs: generic,atempo,bakbone,commvault,emc,symantec,tivoli,symantec-netbackup,symantec-backupexec

.PARAMETER msb_context_retention_duration
	Multi-Stream Backup context retention duration.

.PARAMETER msr_context_retention_duration
	Multi-Stream Restore context retention duration.

.PARAMETER port
	The port to listen on.

.PARAMETER service
	Property to enable/diable the NDMP service.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$bre_max_num_contexts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('generic','atempo','bakbone','commvault','emc','symantec','tivoli','symantec-netbackup','symantec-backupexec')][string]$dma,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$msb_context_retention_duration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$msr_context_retention_duration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$port,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNdmpSettingsGlobal')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ndmp/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNdmpSettingsGlobal

function Set-isiNdmpSettingsVariable{
<#
.SYNOPSIS
	Set Protocols Ndmp Settings Variable

.DESCRIPTION
	Modify or create a NDMP preferred environment variable.

.PARAMETER id
	Path id

.PARAMETER value
	The value of environment variable.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$value,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			$parameter1 = $id
			$BoundParameters.Remove('id') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNdmpSettingsVariable')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ndmp/settings/variables/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNdmpSettingsVariable

function Set-isiNdmpUser{
<#
.SYNOPSIS
	Set Protocols Ndmp User

.DESCRIPTION
	Modify the user

.PARAMETER id
	Name id

.PARAMETER name
	Name name

.PARAMETER password
	The password for the NDMP administrator.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNdmpUser')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ndmp/users/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNdmpUser

function Set-isiNfsAlias{
<#
.SYNOPSIS
	Set Nfs Aliase

.DESCRIPTION
	Modify the alias. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Aid id

.PARAMETER name
	Aid name

.PARAMETER health
	Specifies whether the alias is usable.

.PARAMETER new_name
	Specifies the name by which the alias can be referenced.

.PARAMETER path
	Specifies the path to which the alias points.

.PARAMETER zone
	Specifies the zone in which the alias is valid.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][object]$health,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsAlias')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/2/protocols/nfs/aliases/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsAlias

function Set-isiNfsExportv1{
<#
.SYNOPSIS
	Set Nfs Export

.DESCRIPTION
	Modify the export. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	 id

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
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_datasync_reply
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_action
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_reply
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_transfer_max_size
	The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_unstable_reply
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER Force
	Force update of object without prompt

.PARAMETER enforce
	If true, the export will be updated even if that change conflicts with another export.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][array]$paths,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=40)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][ValidateNotNullOrEmpty()][bool]$enforce,
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
				$BoundParameters.Remove('enforce') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsExportv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/protocols/nfs/exports/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsExportv1

function Set-isiNfsExportv2{
<#
.SYNOPSIS
	Set Nfs Export

.DESCRIPTION
	Modify the export. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	 id

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
	User and group mapping.

.PARAMETER map_failure
	User and group mapping.

.PARAMETER map_full
	True if user mappings query the OneFS user database. When set to false, user mappings only query local authentication.

.PARAMETER map_lookup_uid
	True if incoming user IDs (UIDs) are mapped to users in the OneFS user database. When set to false, incoming UIDs are applied directly to file operations.

.PARAMETER map_non_root
	User and group mapping.

.PARAMETER map_retry
	Determines whether searches for users specified in 'map_all', 'map_root' or 'map_nonroot' are retried if the search fails.

.PARAMETER map_root
	User and group mapping.

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
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_datasync_reply
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_action
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_reply
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_transfer_max_size
	Specifies the maximum buffer size that clients should use on NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_transfer_multiple
	Specifies the preferred multiple size for NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_transfer_size
	Specifies the preferred multiple size for NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_unstable_action
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_unstable_reply
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER zone
	Specifies the zone in which the export is valid.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER enforce
	If true, the export will be updated even if that change conflicts with another export.

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$case_insensitive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$case_preserving,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$chown_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$link_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][object]$map_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][object]$map_non_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$name_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$no_truncate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$paths,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$read_only_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$read_write_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][array]$root_clients,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=47)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=49)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=50)][ValidateNotNullOrEmpty()][bool]$enforce,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=51)][ValidateNotNullOrEmpty()][string]$access_zone,
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
				$BoundParameters.Remove('enforce') | out-null
			}
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsExportv2')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/2/protocols/nfs/exports/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsExportv2
Set-Alias Set-isiNfsExport -Value Set-isiNfsExportv2
Export-ModuleMember -Alias Set-isiNfsExport

function Set-isiNfsLogLevel{
<#
.SYNOPSIS
	Set Protocols Nfs Log Level

.DESCRIPTION
	Set the current NFS service logging level.

.PARAMETER level
	Valid NFS logging levels
	Valid inputs: always,error,warning,info,verbose,debug,trace

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('always','error','warning','info','verbose','debug','trace')][string]$level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsLogLevel')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/nfs/log-level" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsLogLevel

function Set-isiNfsNetgroup{
<#
.SYNOPSIS
	Set Protocols Nfs Netgroup

.DESCRIPTION
	Modify the current NFS netgroup settings.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER host
	Host to retrieve netgroup cache settings for.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=0)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateNotNullOrEmpty()][string]$host,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsNetgroup')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/protocols/nfs/netgroup" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsNetgroup

function Set-isiNfsSettingsExportv1{
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
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_datasync_reply
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_action
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_reply
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_transfer_max_size
	The maximum buffer size that clients should use on NFS write requests.  This option is advisory.

.PARAMETER write_transfer_multiple
	The preferred multiple size for NFS write requests.  This option is advisory.

.PARAMETER write_transfer_size
	The optimal size for NFS read requests.  This option is advisory.

.PARAMETER write_unstable_action
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_unstable_reply
	The synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=33)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsExportv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/nfs/settings/export" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsExportv1

function Set-isiNfsSettingsExportv2{
<#
.SYNOPSIS
	Set Nfs Settings Export

.DESCRIPTION
	Modify the default values for NFS exports. All input fields are optional, but one or more must be supplied.

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

.PARAMETER commit_asynchronous
	True if NFS  commit  requests execute asynchronously.

.PARAMETER directory_transfer_size
	Specifies the preferred size for directory read operations. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER encoding
	Specifies the default character set encoding of the clients connecting to the export, unless otherwise specified.

.PARAMETER link_max
	Specifies the reported maximum number of links to a file. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER map_all
	User and group mapping.

.PARAMETER map_failure
	User and group mapping.

.PARAMETER map_full
	True if user mappings query the OneFS user database. When set to false, user mappings only query local authentication.

.PARAMETER map_lookup_uid
	True if incoming user IDs (UIDs) are mapped to users in the OneFS user database. When set to false, incoming UIDs are applied directly to file operations.

.PARAMETER map_non_root
	User and group mapping.

.PARAMETER map_retry
	Determines whether searches for users specified in 'map_all', 'map_root' or 'map_nonroot' are retried if the search fails.

.PARAMETER map_root
	User and group mapping.

.PARAMETER max_file_size
	Specifies the maximum file size for any file accessed from the export. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER name_max_size
	Specifies the reported maximum length of a file name. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER no_truncate
	True if long file names result in an error. This parameter does not affect server behavior, but is included to accommodate legacy client requirements.

.PARAMETER readdirplus
	True if 'readdirplus' requests are enabled. Enabling this property might improve network performance and is only available for NFSv3.

.PARAMETER readdirplus_prefetch
	Sets the number of directory entries that are prefetched when a 'readdirplus' request is processed. (Deprecated.)

.PARAMETER read_only
	True if the export is set to read-only.

.PARAMETER read_transfer_max_size
	Specifies the maximum buffer size that clients should use on NFS read requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER read_transfer_multiple
	Specifies the preferred multiple size for NFS read requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER read_transfer_size
	Specifies the preferred size for NFS read requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER return_32bit_file_ids
	Limits the size of file identifiers returned by NFSv3+ to 32-bit values.

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
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_datasync_reply
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_action
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_filesync_reply
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_transfer_max_size
	Specifies the maximum buffer size that clients should use on NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_transfer_multiple
	Specifies the preferred multiple size for NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_transfer_size
	Specifies the preferred multiple size for NFS write requests. This value is used to advise the client of optimal settings for the server, but is not enforced.

.PARAMETER write_unstable_action
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER write_unstable_reply
	Specifies the synchronization type.
	Valid inputs: DATASYNC,FILESYNC,UNSTABLE

.PARAMETER zone
	Specifies the zone in which the export is valid.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Access zone

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$all_dirs,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$block_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$can_set_time,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$case_insensitive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$case_preserving,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$chown_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$commit_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$directory_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$encoding,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$link_max,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][object]$map_all,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][object]$map_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$map_full,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$map_lookup_uid,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][object]$map_non_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$map_retry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][object]$map_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$max_file_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$name_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$no_truncate,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$readdirplus,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$readdirplus_prefetch,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$read_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$read_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][int]$read_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$read_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$return_32bit_file_ids,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$security_flavors,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$setattr_asynchronous,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][string]$snapshot,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$symlinks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][object]$time_delta,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_datasync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_filesync_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$write_transfer_max_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][int]$write_transfer_multiple,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][int]$write_transfer_size,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateSet('DATASYNC','FILESYNC','UNSTABLE')][string]$write_unstable_reply,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=42)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsExportv2')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/2/protocols/nfs/settings/export" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsExportv2
Set-Alias Set-isiNfsSettingsExport -Value Set-isiNfsSettingsExportv2
Export-ModuleMember -Alias Set-isiNfsSettingsExport

function Set-isiNfsSettingsGlobalv3{
<#
.SYNOPSIS
	Set Protocols Nfs Settings Global

.DESCRIPTION
	Modify the default values for NFS exports. All input fields are optional, but one or more must be supplied.

.PARAMETER nfsv3_enabled
	True if NFSv3 is enabled.

.PARAMETER nfsv4_enabled
	True if NFSv4 is enabled.

.PARAMETER rpc_maxthreads
	Specifies the maximum number of threads in the nfsd thread pool.

.PARAMETER rpc_minthreads
	Specifies the minimum number of threads in the nfsd thread pool.

.PARAMETER service
	True if the NFS service is enabled. When set to false, the NFS service is disabled.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$nfsv3_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$nfsv4_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$rpc_maxthreads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$rpc_minthreads,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=5)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsGlobalv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/nfs/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsGlobalv3

function Set-isiNfsSettingsZone{
<#
.SYNOPSIS
	Set Nfs Settings Zone

.DESCRIPTION
	Modify the NFS server settings for this zone.

.PARAMETER nfsv4_allow_numeric_ids
	If true, sends owners and groups as UIDs and GIDs when look up fails or if the 'nfsv4_no_name' property is set to 1.

.PARAMETER nfsv4_domain
	Specifies the domain or realm through which users and groups are associated.

.PARAMETER nfsv4_no_domain
	If true, sends owners and groups without a domain name.

.PARAMETER nfsv4_no_domain_uids
	If true, sends UIDs and GIDs without a domain name.

.PARAMETER nfsv4_no_names
	If true, sends owners and groups as UIDs and GIDs.

.PARAMETER nfsv4_replace_domain
	If true, replaces the owner or group domain with an NFS domain name.

.PARAMETER zone
	Specifies the access zones in which these settings apply.

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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNfsSettingsZone')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/2/protocols/nfs/settings/zone" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNfsSettingsZone

function Set-isiNtpServer{
<#
.SYNOPSIS
	Set Protocols Ntp Server

.DESCRIPTION
	Modify the key value for an NTP server.

.PARAMETER id
	Server id

.PARAMETER name
	Server name

.PARAMETER key
	Key value from key_file that maps to this server.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$key,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNtpServer')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ntp/servers/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNtpServer

function Set-isiNtpSettings{
<#
.SYNOPSIS
	Set Protocols Ntp Settings

.DESCRIPTION
	Modify the NTP settings. All input fields are optional, but one or more must be supplied.

.PARAMETER chimers
	Number of nodes that will contact the NTP servers.

.PARAMETER excluded
	Node number (LNN) for nodes excluded from chimer duty.

.PARAMETER key_file
	Path to NTP key file within /ifs.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][int]$chimers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][array]$excluded,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$key_file,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=3)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiNtpSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/ntp/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiNtpSettings

function Set-isiSmbLogLevel{
<#
.SYNOPSIS
	Set Protocols Smb Log Level

.DESCRIPTION
	Set the current SMB logging level.

.PARAMETER level
	Valid SMB logging levels
	Valid inputs: always,error,warning,info,verbose,debug,trace

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('always','error','warning','info','verbose','debug','trace')][string]$level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbLogLevel')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/smb/log-level" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbLogLevel

function Set-isiSmbSettingsGlobalv1{
<#
.SYNOPSIS
	Set Smb Settings Global

.DESCRIPTION
	Modify one or more settings.

.PARAMETER access_based_share_enum
	Only enumerate files and folders the requesting user has access to.

.PARAMETER audit_fileshare
	Specify level of file share audit events to log.
	Valid inputs: all,success,failure,none

.PARAMETER audit_global_sacl
	Specifies a list of permissions to audit.

.PARAMETER audit_logon
	Specify the level of logon audit events to log.
	Valid inputs: all,success,failure,none

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('all','success','failure','none')][string]$audit_fileshare,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$audit_global_sacl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('all','success','failure','none')][string]$audit_logon,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSettingsGlobalv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/protocols/smb/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSettingsGlobalv1
Set-Alias Set-isiSmbSettingsGlobal -Value Set-isiSmbSettingsGlobalv1
Export-ModuleMember -Alias Set-isiSmbSettingsGlobal

function Set-isiSmbSettingsGlobalv3{
<#
.SYNOPSIS
	Set Protocols Smb Settings Global

.DESCRIPTION
	Modify one or more settings.

.PARAMETER access_based_share_enum
	Only enumerate files and folders the requesting user has access to.

.PARAMETER audit_fileshare
	Specify level of file share audit events to log.
	Valid inputs: all,success,failure,none

.PARAMETER audit_global_sacl
	Specifies a list of permissions to audit.

.PARAMETER audit_logon
	Specify the level of logon audit events to log.
	Valid inputs: all,success,failure,none

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

.PARAMETER server_side_copy
	Enable Server Side Copy.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('all','success','failure','none')][string]$audit_fileshare,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$audit_global_sacl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][ValidateSet('all','success','failure','none')][string]$audit_logon,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][bool]$server_side_copy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$server_string,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$srv_cpu_multiplier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$srv_num_workers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$support_multichannel,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$support_netbios,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$support_smb2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=22)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSettingsGlobalv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/smb/settings/global" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSettingsGlobalv3

function Set-isiSmbSettingsSharev1{
<#
.SYNOPSIS
	Set Smb Settings Share

.DESCRIPTION
	Modify one or more settings.

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
	Valid inputs: all,norecurse,none

.PARAMETER create_permissions
	Set the create permissions for new files and directories in share.
	Valid inputs: default acl,inherit mode bits,use create mask and mode

.PARAMETER csc_policy
	Client-side caching policy for the shares.
	Valid inputs: manual,documents,programs,none

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
	Valid inputs: always,bad user,never

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

.PARAMETER zone
	Name of the access zone in which to update settings

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Zone which contains these share settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][ValidateSet('all','norecurse','none')][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][ValidateSet('always','bad user','never')][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][array]$mangle_map,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$oplocks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=22)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSettingsSharev1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/protocols/smb/settings/share" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSettingsSharev1
Set-Alias Set-isiSmbSettingsShare -Value Set-isiSmbSettingsSharev1
Export-ModuleMember -Alias Set-isiSmbSettingsShare

function Set-isiSmbSettingsSharev3{
<#
.SYNOPSIS
	Set Protocols Smb Settings Share

.DESCRIPTION
	Modify one or more settings.

.PARAMETER access_based_enumeration
	Only enumerate files and folders the requesting user has access to.

.PARAMETER access_based_enumeration_root_only
	Access-based enumeration on only the root directory of the share.

.PARAMETER allow_delete_readonly
	Allow deletion of read-only files in the share.

.PARAMETER allow_execute_always
	Allows users to execute files they have read rights for.

.PARAMETER ca_timeout
	Persistent open timeout for the share.

.PARAMETER ca_write_integrity
	Specify the level of write-integrity on continuously available shares.
	Valid inputs: none,write-read-coherent,full

.PARAMETER change_notify
	Specify level of change notification alerts on the share.
	Valid inputs: all,norecurse,none

.PARAMETER create_permissions
	Set the create permissions for new files and directories in share.
	Valid inputs: default acl,inherit mode bits,use create mask and mode

.PARAMETER csc_policy
	Client-side caching policy for the shares.
	Valid inputs: manual,documents,programs,none

.PARAMETER directory_create_mask
	Unix umask or mode bits.

.PARAMETER directory_create_mode
	Unix umask or mode bits.

.PARAMETER file_create_mask
	Unix umask or mode bits.

.PARAMETER file_create_mode
	Unix umask or mode bits.

.PARAMETER file_filtering_enabled
	Enables file filtering on the share.

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

.PARAMETER mangle_byte_start
	Specifies the wchar_t starting point for automatic byte mangling.

.PARAMETER mangle_map
	Character mangle map.

.PARAMETER ntfs_acl_support
	Support NTFS ACLs on files and directories.

.PARAMETER oplocks
	Allow oplock requests.

.PARAMETER strict_ca_lockout
	Specifies if persistent opens would do strict lockout on the share.

.PARAMETER strict_flush
	Handle SMB flush operations.

.PARAMETER strict_locking
	Specifies whether byte range locks contend against SMB I/O.

.PARAMETER zone
	Name of the access zone in which to update settings

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Zone which contains these share settings.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$ca_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('none','write-read-coherent','full')][string]$ca_write_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('all','norecurse','none')][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$file_filtering_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$file_filter_extensions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][ValidateSet('deny','allow')][string]$file_filter_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][ValidateSet('always','bad user','never')][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][array]$mangle_map,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$oplocks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$strict_ca_lockout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=28)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSettingsSharev3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/protocols/smb/settings/share" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSettingsSharev3

function Set-isiSmbSharev1{
<#
.SYNOPSIS
	Set Smb Share

.DESCRIPTION
	Modify share. All input fields are optional, but one or must be supplied.

.PARAMETER id
	Share id

.PARAMETER name
	Share name

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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Zone which contains this share.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$allow_variable_expansion,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$auto_create_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$browsable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('all','norecurse','none')][string]$change_notify,
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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$oplocks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][array]$run_as_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=32)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSharev1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/1/protocols/smb/shares/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSharev1
Set-Alias Set-isiSmbShare -Value Set-isiSmbSharev1
Export-ModuleMember -Alias Set-isiSmbShare

function Set-isiSmbSharev3{
<#
.SYNOPSIS
	Set Protocols Smb Share

.DESCRIPTION
	Modify share. All input fields are optional, but one or must be supplied.

.PARAMETER id
	Share id

.PARAMETER name
	Share name

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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER access_zone
	Zone which contains this share.

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$access_based_enumeration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$access_based_enumeration_root_only,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$allow_delete_readonly,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$allow_execute_always,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$allow_variable_expansion,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$auto_create_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$browsable,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][int]$ca_timeout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('none','write-read-coherent','full')][string]$ca_write_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateSet('all','norecurse','none')][string]$change_notify,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][int]$directory_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][int]$directory_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$file_create_mask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][int]$file_create_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$file_filtering_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$file_filter_extensions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][ValidateSet('deny','allow')][string]$file_filter_type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][bool]$hide_dot_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$host_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][ValidateSet('always','bad user','never')][string]$impersonate_guest,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][string]$impersonate_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][bool]$inheritable_path_acl,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][int]$mangle_byte_start,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][array]$mangle_map,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$ntfs_acl_support,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$oplocks,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][array]$permissions,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][array]$run_as_root,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][bool]$strict_ca_lockout,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$strict_flush,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][bool]$strict_locking,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=38)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateNotNullOrEmpty()][string]$access_zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			$queryArguments = @()
			if ($access_zone){
				$queryArguments += 'zone=' + $access_zone
				$BoundParameters.Remove('access_zone') | out-null
			}
			if ($queryArguments) {
				$queryArguments = '?' + [String]::Join('&',$queryArguments)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSmbSharev3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource ("/platform/3/protocols/smb/shares/$parameter1" + "$queryArguments") -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSmbSharev3

function Set-isiSnmpSettings{
<#
.SYNOPSIS
	Set Protocols Snmp Settings

.DESCRIPTION
	Modify the SNMO settings. All input fields are optional, but one or more must be supplied.

.PARAMETER read_only_community
	The read-only community name.  @DEFAULT reverts this field to its default value.

.PARAMETER service
	Whether the SNMP service is enabled.

.PARAMETER snmp_v1_v2c_access
	Whether SNMP v1 and v2c protocols are enabled.  @DEFAULT reverts this field to its default value.

.PARAMETER snmp_v3_access
	Whether SNMP v3 is enabled.  @DEFAULT reverts this field to its default value.

.PARAMETER snmp_v3_password
	This field allows a client to change the SNMP v3 password. There is always a password set.  @DEFAULT reverts this field to its default value.

.PARAMETER snmp_v3_read_only_user
	The read-only user for SNMP v3 read requests.  @DEFAULT reverts this field to its default value.

.PARAMETER system_contact
	Contact information for the system owner.  This must be a valid email address.  @DEFAULT reverts this field to its default value.

.PARAMETER system_location
	A location name for the SNMP system.  @DEFAULT reverts this field to its default value.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][string]$read_only_community,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$snmp_v1_v2c_access,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$snmp_v3_access,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$snmp_v3_password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$snmp_v3_read_only_user,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$system_contact,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$system_location,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnmpSettings')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/snmp/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnmpSettings

function Set-isiSwiftAccount{
<#
.SYNOPSIS
	Set Protocols Swift Account

.DESCRIPTION
	Modify a Swift account

.PARAMETER id
	Account id

.PARAMETER name
	Account name

.PARAMETER new_id
	Unique id of swift account

.PARAMETER new_name
	Name of Swift account

.PARAMETER swiftgroup
	Group with filesystem ownership of this account

.PARAMETER swiftuser
	User with filesystem ownership of this account

.PARAMETER users
	Users who are allowed to access Swift account

.PARAMETER zone
	Name of access zone for account

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$new_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$swiftgroup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$swiftuser,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][array]$users,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$zone,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_id){
				$BoundParameters.Remove('new_id') | out-null
				$BoundParameters.Add('id',$new_id)
			}
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSwiftAccount')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/protocols/swift/accounts/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSwiftAccount

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuota')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/quotas/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaNotifications')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/quotas/$parameter1/notifications" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$quota_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$quota_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$action_email_owner,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter2 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaNotification')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/quotas/$parameter1/notifications/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaSettingsMapping')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/settings/mappings/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$action_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$action_email_address,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$action_email_owner,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$email_template,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$holdoff,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=7)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiQuotaSettingsNotification')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/quota/settings/notifications/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
			return $ISIObject
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
	Email the customer if all transmission methods fail.

.PARAMETER enabled
	Enable ConnectEMC.

.PARAMETER gateway_access_pools
	List of network pools that are able to connect to the ESRS gateway.  Necessary to enable ConnectEMC.

.PARAMETER primary_esrs_gateway
	Primary ESRS Gateway. Necessary to enable ConnectEMC.

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$gateway_access_pools,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$primary_esrs_gateway,
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
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
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
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$expires,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshot')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/snapshots/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$snapshot_id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$snapshot_name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=1,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('snapshot_id')){
				$parameter1 = $snapshot_id
				$BoundParameters.Remove('snapshot_id') | out-null
			} else {
				$parameter1 = $snapshot_name
				$BoundParameters.Remove('snapshot_name') | out-null
			}
			if ($psBoundParameters.ContainsKey('id')){
				$parameter2 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter2 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSnapshotLock')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/snapshot/snapshots/$parameter1/locks/$parameter2" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSnapshotLock

function Set-isiStoragepoolCompatibilitiesSSDActivev3{
<#
.SYNOPSIS
	Set Storagepool Compatibilities Ssd Active

.DESCRIPTION
	Modify an ssd compatibility by id

.PARAMETER id
	Id id

.PARAMETER name
	Id name

.PARAMETER assess
	Do not delete ssd compatibility, only assess if deletion is possible.

.PARAMETER count
	Are we enabling or disabling count

.PARAMETER id_2
	The optional id of the second ssd compatibility.

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$assess,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$id_2,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=4)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiStoragepoolCompatibilitiesSSDActivev3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/storagepool/compatibilities/ssd/active/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolCompatibilitiesSSDActivev3

function Set-isiStoragepoolNodepoolv1{
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$l3,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$lnns,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$protection_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$tier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiStoragepoolNodepoolv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/storagepool/nodepools/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolNodepoolv1
Set-Alias Set-isiStoragepoolNodepool -Value Set-isiStoragepoolNodepoolv1
Export-ModuleMember -Alias Set-isiStoragepoolNodepool

function Set-isiStoragepoolNodepoolv3{
<#
.SYNOPSIS
	Set Storagepool Nodepool

.DESCRIPTION
	Modify node pool. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Nid id

.PARAMETER name
	Nid name

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$l3,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$lnns,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][string]$protection_policy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][string]$tier,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=6)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiStoragepoolNodepoolv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/storagepool/nodepools/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolNodepoolv3

function Set-isiStoragepoolSettings{
<#
.SYNOPSIS
	Set Storagepool Settings

.DESCRIPTION
	Modify one or more settings.

.PARAMETER automatically_manage_io_optimization
	Automatically manage IO optimization settings on files.
	Valid inputs: all,files_at_default,none

.PARAMETER automatically_manage_protection
	Automatically manage protection settings on files.
	Valid inputs: all,files_at_default,none

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][ValidateSet('all','files_at_default','none')][string]$automatically_manage_io_optimization,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('all','files_at_default','none')][string]$automatically_manage_protection,
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
			return $ISIObject
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiStoragepoolTier

function Set-isiSyncJobv1{
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
	Valid inputs: canceled,running,paused

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('canceled','running','paused')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncJobv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/jobs/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncJobv1
Set-Alias Set-isiSyncJob -Value Set-isiSyncJobv1
Export-ModuleMember -Alias Set-isiSyncJob

function Set-isiSyncJobv3{
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
	Valid inputs: canceled,running,paused

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('canceled','running','paused')][string]$state,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=2)][switch]$Force,
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncJobv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/sync/jobs/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncJobv3

function Set-isiSyncPolicyv1{
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
	Valid inputs: copy,sync

.PARAMETER burst_mode
	NOTE: This field should not be changed without the help of Isilon support.  Enable/disable UDP-based data transfer.

.PARAMETER changelist
	If true, retain previous source snapshot and incremental repstate, both of which are required for changelist creation.

.PARAMETER check_integrity
	If true, the sync target performs cyclic redundancy checks (CRC) on the data as it is received.

.PARAMETER conflicted
	NOTE: This field should not be changed without the help of Isilon support.  If true, the most recent run of this policy encountered an error and this policy will not start any more scheduled jobs until this field is manually set back to 'false'.
	Valid inputs: False

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][ValidateSet('copy','sync')][string]$action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][bool]$burst_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$changelist,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$check_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][ValidateSet('False')][bool]$conflicted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$disable_file_split,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][bool]$disable_fofb,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$disable_stf,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$expected_dataloss,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$force_interface,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][ValidateSet('fatal','error','notice','info','copy','debug','trace')][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$log_removed_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][int]$report_max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][int]$report_max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$restrict_target_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$source_exclude_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][array]$source_include_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][object]$source_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][string]$source_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][bool]$source_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][int]$source_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][string]$source_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$target_compare_initial_sync,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][bool]$target_detect_modifications,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][string]$target_host,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][string]$target_snapshot_alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][bool]$target_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][int]$target_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][string]$target_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=38)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncPolicyv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncPolicyv1
Set-Alias Set-isiSyncPolicy -Value Set-isiSyncPolicyv1
Export-ModuleMember -Alias Set-isiSyncPolicy

function Set-isiSyncPolicyv3{
<#
.SYNOPSIS
	Set Sync Policy

.DESCRIPTION
	Modify a single SyncIQ policy.

.PARAMETER id
	Policy id

.PARAMETER name
	Policy name

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

.PARAMETER conflicted
	NOTE: This field should not be changed without the help of Isilon support.  If true, the most recent run of this policy encountered an error and this policy will not start any more scheduled jobs until this field is manually set back to 'false'.
	Valid inputs: False

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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$accelerated_failback,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateSet('copy','sync')][string]$action,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][bool]$burst_mode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$changelist,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$check_integrity,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('deny','allow','force')][string]$cloud_deep_copy,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('False')][bool]$conflicted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$description,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][bool]$disable_file_split,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][bool]$disable_fofb,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][bool]$disable_stf,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][bool]$enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][bool]$expected_dataloss,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][object]$file_matching_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][bool]$force_interface,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][int]$job_delay,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][ValidateSet('fatal','error','notice','info','copy','debug','trace')][string]$log_level,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][bool]$log_removed_files,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][string]$password,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][int]$priority,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][int]$report_max_age,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][int]$report_max_count,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=24)][bool]$restrict_target_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][int]$rpo_alert,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=26)][string]$schedule,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=27)][bool]$skip_lookup,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=28)][bool]$skip_when_source_unmodified,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=29)][bool]$snapshot_sync_existing,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=30)][string]$snapshot_sync_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=31)][array]$source_exclude_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=32)][array]$source_include_directories,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=33)][object]$source_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=34)][string]$source_root_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=35)][bool]$source_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=36)][int]$source_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=37)][string]$source_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=38)][bool]$target_compare_initial_sync,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=39)][bool]$target_detect_modifications,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=40)][string]$target_host,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=41)][string]$target_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=42)][string]$target_snapshot_alias,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=43)][bool]$target_snapshot_archive,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=44)][int]$target_snapshot_expiration,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=45)][string]$target_snapshot_pattern,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=46)][int]$workers_per_node,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=47)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=48)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncPolicyv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/sync/policies/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncPolicyv3

function Set-isiSyncRulev1{
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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncRulev1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/rules/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncRulev1
Set-Alias Set-isiSyncRule -Value Set-isiSyncRulev1
Export-ModuleMember -Alias Set-isiSyncRule

function Set-isiSyncRulev3{
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
	Amount the specified system resource type is limited by this rule.  Units are kb/s for bandwidth, files/s for file-count, processing percentage used for cpu, or percentage of maximum available workers.

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
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
			if ($psBoundParameters.ContainsKey('id')){
				$parameter1 = $id
				$BoundParameters.Remove('id') | out-null
			} else {
				$parameter1 = $name
				$BoundParameters.Remove('name') | out-null
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncRulev3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/sync/rules/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncRulev3

function Set-isiSyncSettingsv1{
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
	Valid inputs: on,off,paused

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('on','off','paused')][string]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][object]$source_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=9)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncSettingsv1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/sync/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncSettingsv1
Set-Alias Set-isiSyncSettings -Value Set-isiSyncSettingsv1
Export-ModuleMember -Alias Set-isiSyncSettings

function Set-isiSyncSettingsv3{
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

.PARAMETER rpo_alerts
	If disabled, no RPO alerts will be generated.

.PARAMETER service
	Specifies if the SyncIQ service currently on, paused, or off.  If paused, all sync jobs will be paused.  If turned off, all jobs will be canceled.
	Valid inputs: on,off,paused

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
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][bool]$rpo_alerts,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][ValidateSet('on','off','paused')][string]$service,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][object]$source_network,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=10)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiSyncSettingsv3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/sync/settings" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiSyncSettingsv3

function Set-isiUpgradeClusterUpgrade{
<#
.SYNOPSIS
	Set Upgrade Cluster Upgrade

.DESCRIPTION
	Add nodes to a running upgrade.

.PARAMETER nodes_to_rolling_upgrade
	The nodes (to be) scheduled for an existing upgrade ordered by queue position number. [<lnn-1>, <lnn-2>, ... ], 'All', null

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=0)][array]$nodes_to_rolling_upgrade,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=1)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{
			$BoundParameters = $PSBoundParameters
			$BoundParameters.Remove('Cluster') | out-null
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiUpgradeClusterUpgrade')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/upgrade/cluster/upgrade" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiUpgradeClusterUpgrade

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
	Specifies the autocommit time period for the domain in seconds.  After a file is in the domain without being modified for the specified time period, the file is automatically committed. If this parameter is set to null, there is no autocommit time, and files must be committed manually.

.PARAMETER default_retention
	Specifies the default amount of time, in seconds, that a file in this domain will be protected for. The default retention period is applied if no retention date is manually set on the file. This parameter can also be set to 'forever', 'use_min' (which applies the 'min_retention' option), or 'use_max' (which applies the 'max_retention' option).

.PARAMETER max_retention
	Specifies the maximum amount of time, in seconds, that a file in this domain will be protected. This setting will override the retention period of any file committed with a longer retention period. If this parameter is set to null, an infinite length retention period is set.

.PARAMETER min_retention
	Specifies the minimum amount of time, in seconds, that a file in this domain will be protected. This setting will override the retention period of any file committed with a shorter retention period. If this parameter is set to null, this minimum value is not enforced. This parameter can also be set to 'forever'.

.PARAMETER override_date
	Specifies the override retention date for the domain. If this date is later than the retention date for any committed file, the file will remain protected until the override retention date.

.PARAMETER privileged_delete
	When this value is set to 'on', files in this domain can be deleted through the privileged delete feature. If this value is set to 'disabled', privileged file deletes are permanently disabled and cannot be turned on again.
	Valid inputs: on,off,disabled

.PARAMETER type
	Specifies whether the domain is an enterprise domain or a compliance domain. Compliance domains can not be created on enterprise clusters. Enterprise and compliance domains can be created on compliance clusters.
	Valid inputs: enterprise,compliance

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][int]$autocommit_offset,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][int]$default_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$max_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][int]$min_retention,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][int]$override_date,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][ValidateSet('on','off','disabled')][string]$privileged_delete,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][ValidateSet('enterprise','compliance')][string]$type,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=8)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiWormDomain')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/worm/domains/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
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
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiWormSettings

function Set-isiZonev1{
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

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][bool]$all_auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][string]$alternate_system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][array]$audit_failure,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][array]$audit_success,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][array]$auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][string]$hdfs_ambari_namenode,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$hdfs_ambari_server,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][ValidateSet('all','simple_only','kerberos_only')][string]$hdfs_authentication,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$hdfs_root_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][int]$home_directory_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][array]$ifs_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$map_untrusted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=15)][string]$netbios_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=17)][bool]$protocol_audit_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=18)][string]$skeleton_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=19)][array]$syslog_audit_events,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=20)][bool]$syslog_forwarding_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=21)][string]$system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=22)][array]$user_mapping_rules,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=23)][bool]$webhdfs_enabled,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=24)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=25)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiZonev1')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/1/zones/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiZonev1
Set-Alias Set-isiZone -Value Set-isiZonev1
Export-ModuleMember -Alias Set-isiZone

function Set-isiZonev3{
<#
.SYNOPSIS
	Set Zone

.DESCRIPTION
	Modify the access zone. All input fields are optional, but one or more must be supplied.

.PARAMETER id
	Zone id

.PARAMETER name
	Zone name

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

.PARAMETER home_directory_umask
	Specifies the permissions set on automatically created user home directories.

.PARAMETER ifs_restricted
	Specifies a list of users and groups that have read and write access to /ifs.

.PARAMETER map_untrusted
	Maps untrusted domains to this NetBIOS domain during authentication.

.PARAMETER new_name
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

.PARAMETER Force
	Force update of object without prompt

.PARAMETER Cluster
	Name of Isilon Cluster

.NOTES

#>
	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High',DefaultParametersetName='ByID')]
		param (
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByID')][ValidateNotNullOrEmpty()][string]$id,
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0,ParameterSetName='ByName')][ValidateNotNullOrEmpty()][string]$name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=1)][string]$alternate_system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=2)][array]$auth_providers,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=3)][int]$cache_entry_expiry,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=4)][bool]$create_path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=5)][bool]$force_overlap,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=6)][int]$home_directory_umask,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=7)][array]$ifs_restricted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=8)][string]$map_untrusted,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=9)][string]$new_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=10)][string]$netbios_name,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=11)][string]$path,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=12)][string]$skeleton_directory,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=13)][string]$system_provider,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=14)][array]$user_mapping_rules,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$False,Position=15)][switch]$Force,
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$False,Position=16)][ValidateNotNullOrEmpty()][string]$Cluster
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
			if ($new_name){
				$BoundParameters.Remove('new_name') | out-null
				$BoundParameters.Add('name',$new_name)
			}
			if ($Force -or $PSCmdlet.ShouldProcess("$parameter1",'Set-isiZonev3')){
				$ISIObject = Send-isiAPI -Method PUT -Resource "/platform/3/zones/$parameter1" -body (convertto-json -depth 40 $BoundParameters) -Cluster $Cluster
			}
			return $ISIObject
	}
	End{
	}
}

Export-ModuleMember -Function Set-isiZonev3


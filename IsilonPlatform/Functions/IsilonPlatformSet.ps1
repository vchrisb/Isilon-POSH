# IsilonPlatform.psm1
#
# The MIT License
#
# Copyright (c) 2014 Christopher Banck.
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

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Set-isiSMBShares{
<#
.SYNOPSIS
    Set Isilon SMB Shares
    
.DESCRIPTION
    Modifies Isilon SMB Shares

.EXAMPLE
    Set-isiSMBShares -name share1 -description 'share for users'

.NOTES

#>
            [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (            
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$access_based_enumeration,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$access_based_enumeration_root_only,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$allow_delete_readonly,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$allow_execute_always,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$allow_variable_expansion,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$auto_create_directory,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$browsable,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('all','norecurse','none')][string]$change_notify,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('default acl','inherit mode bits','use create mask and mode')][string]$create_permissions,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('manual','documents','programs','none')][string]$csc_policy,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$description,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$directory_create_mask,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$directory_create_mode,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$file_create_mask,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$file_create_mode,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$hide_dot_files,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$host_acl,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('always','bad user','never')][string]$impersonate_guest,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$impersonate_user,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$inheritable_path_acl,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$mangle_byte_start,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$mangle_map,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateNotNullOrEmpty()][string]$name,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$ntfs_acl_support,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$oplocks,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$path,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][array]$permissions,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$run_as_root,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$strict_flush,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$strict_locking,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$new_name,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{           
            

    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$name","New-isiSMBShares")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method PUT -Resource "/platform/1/protocols/smb/shares/$name" -body (convertto-json -depth 40 $PSBoundParameters)
                $ISIObject
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function Set-isiSMBShares

function Set-isiZones {
<#
.SYNOPSIS
    Set Isilon Zone
    
.DESCRIPTION
    Modifies Isilon Zone

.EXAMPLE
    Set-isiZones -name ZoneA -new_name ZoneA2

.NOTES

#>

	
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (            
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$all_auth_providers,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$all_smb_shares,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$alternate_system_provider,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$auth_providers,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$cache_size,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$home_directory_umask,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$ifs_restricted,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$local_provider,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$map_untrusted,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateNotNullOrEmpty()][string]$name,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$netbios_name,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$skeleton_directory,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$smb_shares,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$system_provider,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$user_mapping_rules,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$new_name,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{
    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$name","Set-isiZones")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method PUT -Resource "/platform/1/zones/$name" -body (convertto-json -depth 40 $PSBoundParameters)
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function Set-isiZones

function Set-isiQuotas {
<#
.SYNOPSIS
    Set Isilon Quota
    
.DESCRIPTION
    Set Isilon Quota

.EXAMPLE
    Set-isiZones -id AAAlAAEAAAAAAAAAAAAAwAEAAAAAAAAA -thresholds_include_overhead $false

.NOTES

#>

	
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (            
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$container,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$enforced,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$id,
            #[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$force,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$include_snapshots,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$path,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$persona,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$thresholds,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$thresholds_include_overhead,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('directory', 'user', 'group', 'default-user', 'default-group')][string]$type,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{
    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$id","Set-isiZones")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method PUT -Resource "/platform/1/quota/quotas/$id" -body (convertto-json -depth 40 $PSBoundParameters)
                $ISIObject.id
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function Set-isiQuotas

function Set-isiSyncPolicies {
<#
.SYNOPSIS
    Set Isilon SyncIQ Policies
    
.DESCRIPTION
    Set Isilon SyncIQ Policies

.EXAMPLE
    Set-isiSyncPolicies -name sync1 -description 'sync for home shares'

.NOTES

#>

	
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (            
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('copy', 'sync')][string]$action,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$burst_mode,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$check_integrity,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$description,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$enabled,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('fatal', 'error', 'notice', 'info', 'copy', 'debug', 'trace')][string]$log_level,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$log_removed_files,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateNotNullOrEmpty()][string]$name,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$new_name,            
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$password,  
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$report_max_age,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$report_max_count,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$restrict_target_network,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$schedule,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$source_exclude_directories,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$source_include_directories,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][string]$source_network,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$source_root_path,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$source_snapshot_archive,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$source_snapshot_expiration,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$source_snapshot_pattern,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$target_compare_initial_sync,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$target_detect_modifications,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$target_host,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$target_path,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$target_snapshot_alias,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$target_snapshot_archive,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$target_snapshot_expiration,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$target_snapshot_pattern,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][int]$workers_per_node,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{
    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$name","Set-isiSyncPolicies")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method PUT -Resource "/platform/1/sync/policies/$name" -body (convertto-json -depth 40 $PSBoundParameters)
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function Set-isiSyncPolicies
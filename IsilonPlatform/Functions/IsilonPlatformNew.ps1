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

function New-isiSMBShares{
<#
.SYNOPSIS
    New Isilon SMB Shares
    
.DESCRIPTION
    New Isilon SMB Shares

.EXAMPLE
    New-isiSMBShares -name share1 -path '/ifs/data'

.EXAMPLE
    New-isiSMBShares -name share1 -path '/ifs/data' -Cluster Isilon1

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
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$path,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][array]$permissions,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][array]$run_as_root,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$strict_flush,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$strict_locking,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{
            
            
            

    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$name","New-isiSMBShares")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method POST -Resource "/platform/1/protocols/smb/shares" -body (convertto-json -depth 40 $PSBoundParameters)
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function New-isiSMBShares

function New-isiZones{
<#
.SYNOPSIS
    New Isilon SMB Zone
    
.DESCRIPTION
    New Isilon SMB Zone

.EXAMPLE
    New-isiZones -name Zone1

.EXAMPLE
    New-isiZones -Cluster ision1 -name Zone1

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
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{
    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$name","New-isiZones")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method POST -Resource "/platform/1/zones" -body (convertto-json -depth 40 $PSBoundParameters)
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function New-isiZones

function New-isiQuotas{
<#
.SYNOPSIS
    New Isilon Quota
    
.DESCRIPTION
    Create Isilon Quota

.EXAMPLE
    New-isiQuotas -enforced $false -include_snapshots $true -thresholds_include_overhead $true -type directory -path '/ifs/data/zone2'

.NOTES

#>
            [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (            
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$container,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$enforced,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$include_snapshots,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][string]$path,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$persona,
            [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]$thresholds,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][bool]$thresholds_include_overhead,
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)][ValidateNotNullOrEmpty()][ValidateSet('directory', 'user', 'group', 'default-user', 'default-group')][string]$type,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{
    }
    Process{

            if ($Force -or $PSCmdlet.ShouldProcess("$name","New-isiZones")){
                $ISIObject = Send-isiAPI -Cluster $Cluster -Method POST -Resource "/platform/1/quota/quotas" -body (convertto-json -depth 40 $PSBoundParameters)
                $ISIObject.id
            }
    }
    End{

    }
	
}

Export-ModuleMember -Function New-isiQuotas
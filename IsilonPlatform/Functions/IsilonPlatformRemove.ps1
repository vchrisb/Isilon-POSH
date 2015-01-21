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

function Remove-isiSMBShares{
<#
.SYNOPSIS
    Remove Isilon SMB Shares
    
.DESCRIPTION
    Removes Isilon SMB Shares

.EXAMPLE
    Remove-isiSMBShares -name share1

.EXAMPLE
    'share1','share2' | Remove-isiSMBShares


.NOTES

#>

	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string[]]$name,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{ 

    }
    Process{      
        #execute
        if ($Force -or $PSCmdlet.ShouldProcess("$name","Remove-isiSMBShares")){
            $ISIObject = Send-isiAPI -Cluster $Cluster -Method DELETE -Resource "/platform/1/protocols/smb/shares/$name"
        }
    }

    End{

    }
	
}

Export-ModuleMember -Function Remove-isiSMBShares

function Remove-isiZones{
<#
.SYNOPSIS
    Remove Isilon Zone
    
.DESCRIPTION
    Removes Isilon Zone

.EXAMPLE
    Remove-isiZones -name zone1

.EXAMPLE
    'zone1' | Remove-isiZones


.NOTES

#>

	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string[]]$name,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{ 

    }
    Process{      
        #execute
        if ($Force -or $PSCmdlet.ShouldProcess("$name","Remove-isiZones")){
            $ISIObject = Send-isiAPI -Cluster $Cluster -Method DELETE -Resource "/platform/1/zones/$name"
        }
    }

    End{

    }
	
}

Export-ModuleMember -Function Remove-isiZones

function Remove-isiQuotas{
<#
.SYNOPSIS
    Remove Isilon Quota
    
.DESCRIPTION
    Removes Isilon Quota


.EXAMPLE
    Remove-isiQuotas -id DAAhAAEAAAAAAAAAAAAAwAIAAAAAAAAA

.EXAMPLE
    Get-isiQuotas | Where-Object{ $_.path -eq '/ifs/data/zone1'} | Remove-isiSMBShares


.NOTES

#>

	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string[]]$id,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{ 

    }
    Process{      
        #execute
        if ($Force -or $PSCmdlet.ShouldProcess("$name","Remove-isiZones")){
            $ISIObject = Send-isiAPI -Cluster $Cluster -Method DELETE -Resource "/platform/1/quota/quotas/$id"
        }
    }

    End{

    }
	
}

Export-ModuleMember -Function Remove-isiQuotas

function Remove-isiSyncPolicies{
<#
.SYNOPSIS
    Remove Isilon SyncIQ Policy
    
.DESCRIPTION
    Removes Isilon SyncIQ Policy

.EXAMPLE
    Remove-isiSyncPolicies -name sync1

.EXAMPLE
    'sync1','sync2' | Remove-isiSyncPolicies


.NOTES

#>

	[CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='High')]
	
	param (
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string[]]$name,
            [switch]$Force,
            [string]$Cluster=$isi_sessiondefault)

    Begin{ 

    }
    Process{      
        #execute
        if ($Force -or $PSCmdlet.ShouldProcess("$name","Remove-isiSyncPolicies")){
            $ISIObject = Send-isiAPI -Cluster $Cluster -Method DELETE -Resource "/platform/1/sync/policies/$name"
        }
    }

    End{

    }
}

Export-ModuleMember -Function Remove-isiSyncPolicies
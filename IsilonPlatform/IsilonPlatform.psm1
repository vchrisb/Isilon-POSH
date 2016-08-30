# IsilonPlatform.psm1
#
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

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-isiSession{

<#
.SYNOPSIS
    New Isilon Sessison

.DESCRIPTION
    Establishes a new Session with an Isilon Cluster

.PARAMETER ComputerName
IP or FQDN of an Isilon node or SmartConnect address

.PARAMETER Credential
A PSCredential to authenticate against the Isilon

.PARAMETER Cluster
This variable will default to the ComputerName if not set.

.PARAMETER default

.EXAMPLE
    New-isiSession -ComputerName 172.19.20.21 -Cluster Isilon1

.EXAMPLE
    $Credential = Get-Credential
    New-isiSession -ComputerName isilon.domain.com -Credential $Credential -Cluster Isilon2 -default

.EXAMPLE
    $Credential = Get-Credential
    "isilon1.domain.com","isilon2.domain.com" | New-isiSession -Credential $Credential

#>
    [CmdletBinding()]
    Param(
            [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Position=0)][ValidateNotNullOrEmpty()][string] $ComputerName, 
            [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=1)][PSCredential]$Credential = (Get-Credential -Message "Isilon Credential"),
            [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=2)][ValidateNotNullOrEmpty()][string]$Cluster,
            [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=3)][ValidateNotNullOrEmpty()][string]$Port='8080',
            [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,Position=4)][switch]$default)

    Begin{
        
        # test if the isi_session variables already exists
        if(!(Test-Path variable:isi_sessions) ){
            $script:isi_sessions = @()
        }
        if(!(Test-Path variable:isi_sessiondefault) ){
            $script:isi_sessiondefault = ''
        }

    } 
    Process {

        if (!(Test-Path variable:Cluster) -or !$Cluster) {
            $Cluster = $ComputerName
        }

        $ComputerName = ([System.Net.Dns]::GetHostAddresses($ComputerName)).IPAddressToString
        $baseurl = "https://$ComputerName`:$Port"

        #create Jason Object for Input Values
        $jobj = convertto-json @{username= $Credential.UserName; password = $Credential.GetNetworkCredential().Password; services = ('platform','namespace')}

        #create session
        $ISIObject = Invoke-RestMethod -Uri "$baseurl/session/1/session" -Body $jobj -ContentType "application/json; charset=utf-8" -Method POST -SessionVariable session -TimeoutSec 180

        #remove cluster if entry exists
        Clear-isiSession -Cluster $Cluster
        
        #add new cluster
        $script:isi_sessions += New-Object -TypeName psObject -Property @{Cluster = $Cluster; url=$baseurl; session= $session; timeout_absolute=(Get-Date).AddSeconds($ISIObject.timeout_absolute); timeout=(Get-Date).AddSeconds($ISIObject.timeout_inactive); timeout_inactive=$ISIObject.timeout_inactive;username=$ISIObject.username}

        #if default $true or default cluster not present set current cluster 
        if ($default -or (@($isi_sessions | where { $_.cluster -eq $isi_sessiondefault} ).count -eq 0)){
            $script:isi_sessiondefault = $Cluster
        }

        Remove-Variable Cluster

    }
    
    End {
        
        
    }
}

function Get-isiSessionInfo {

<#
.SYNOPSIS
    Get Isilon Sessison Info

.DESCRIPTION

.PARAMETER Cluster

.EXAMPLE
    Get-isiSessionInfo

.EXAMPLE
    Get-isiSessionInfo -Cluster Isilon1

.EXAMPLE
    "isilon1.domain.com","isilon2.domain.com" | Get-isiSessionInfo

.NOTES
    

#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster)

    Begin{
        if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
            Write-Verbose "No Isilon Cluster connected"
            break
        }
        if ( !$psBoundParameters.ContainsKey('Cluster') ) {
            Write-Verbose "No Cluster specified. Selecting session default: $isi_sessiondefault"
            $Cluster = $isi_sessiondefault
        }
    }
    Process{
        Send-isiAPI -Method 'GET' -Resource "/session/1/session" -Cluster $Cluster
    }

    End{

    }
}

function Get-isiSession {

<#
.SYNOPSIS
    Display Isilon Sessisons

.DESCRIPTION

.PARAMETER Cluster

.EXAMPLE
    Get-isiSession

.EXAMPLE
    Get-isiSession -Cluster Isilon1

.NOTES
    

#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster)

    if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
        Write-Verbose "No Isilon Cluster connected!"
        return
    }

    if($isi_sessions){
        if($Cluster){
            $isi_sessions | where { $_.cluster -eq $Cluster }
        }else{
            $isi_sessions    
        }
    }
}

function Clear-isiSession {

<#
.SYNOPSIS
    Clear Isilon Sessison

.DESCRIPTION

.PARAMETER Cluster

.EXAMPLE
    Clear-isiSession

.EXAMPLE
    Clear-isiSession -Cluster Isilon1

.NOTES
    

#>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster)

    if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
        Write-Error "No Isilon Cluster connected!"
    }

    if($Cluster){

        foreach($clust in $Cluster){   
            $script:isi_sessions = @($isi_sessions | where { $_.cluster -ne $clust })
        }

    } Else {
        remove-variable -scope script isi_sessions
        remove-variable -scope script isi_sessiondefault
    }
}

function Remove-isiSession {

<#
.SYNOPSIS
    Removes Isilon Sessison

.DESCRIPTION

.PARAMETER Cluster

.EXAMPLE
    Remove-isiSession

.EXAMPLE
    Remove-isiSession -Cluster Isilon1

.EXAMPLE
    "isilon1.domain.com","isilon2.domain.com" | Remove-isiSession

.NOTES
    

#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster)

    Begin{
        if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
            Write-Error "No Isilon Cluster connected"
            break
        }
        if ( !$psBoundParameters.ContainsKey('Cluster') ) {
            Write-Verbose "No Cluster specified. Selecting session default: $isi_sessiondefault"
            $Cluster = $isi_sessiondefault
        }
    }

    Process{        

        if (@($isi_sessions | where { $_.cluster -eq $Cluster} ).count -eq 1){
            
            #remove session on the isilon cluster
            Send-isiAPI -Resource "/session/1/session" -Cluster $Cluster -Method 'delete'
            #remove entry if exists
            Clear-isiSession -Cluster $Cluster

        }

        if (@($isi_sessions | where { $_.cluster -eq $isi_sessiondefault} ).count -eq 0){
            if ($isi_sessions) {
                $script:isi_sessiondefault = $isi_sessions[0].cluster
            } else {
                Remove-Variable -scope script isi_sessiondefault
            }
        }
        

    }

    End{
    }
        
}

function Get-isiSessionDefault {

<#
.SYNOPSIS
    Display Default Isilon Sessisons

.DESCRIPTION

.EXAMPLE
    Get-isiSession

.NOTES
    

#>

    if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
        Write-Error "No Isilon Cluster connected!"
    }

    $script:isi_sessiondefault
}

function Set-isiSessionDefault {

<#
.SYNOPSIS
     Isilon Sessison

.DESCRIPTION


.EXAMPLE
    Set-isiSessionDefault -Cluster Isilon1

.NOTES
    

#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0)][string]$Cluster)

    Begin{
        if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
            Write-Error "No Isilon Cluster connected!"
        }
    }

    Process{        

        if (@($isi_sessions | where { $_.cluster -eq $Cluster} ).count -eq 1){
            $script:isi_sessiondefault = $Cluster

        }
        else{
            Write-Error "Session for Cluster `"$Cluster`" not found"
        
        }    

    }

    End{
    }
        
}

function Send-isiAPI{

<#
.SYNOPSIS
    sends Rest Command to Ision API

.DESCRIPTION

.PARAMETER Cluster

.PARAMETER Resource

.PARAMETER body

.PARAMETER Method

.EXAMPLE
    Send-isiAPI -Resource "/platform/1/protocols/smb/shares" -Cluster IsilonC1 -Method GET

.NOTES

#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$false,Position=0)][string]$Resource,
    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$false,Position=1)][ValidateSet('GET_JSON','GET','POST','PUT','DELETE','POST')][string]$Method="GET",
    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$false,Position=2)][string]$body,
    [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$False,ValueFromPipeline=$false,Position=3)][string]$Cluster)

    if(!(Test-Path variable:isi_sessions) -or !(Test-Path variable:isi_sessiondefault)){
        Write-Error "No Isilon Cluster connected"
        break
    }
    if ( !$psBoundParameters.ContainsKey('Cluster') -or !$Cluster) {
        Write-Verbose "No Cluster specified. Selecting session default: $isi_sessiondefault"
        $Cluster = $isi_sessiondefault
    }

    $isi_session = Get-isiSession -Cluster $Cluster
    $url = $isi_session.url + $Resource
    $session = $isi_session.session
    $Method = $Method.ToUpper()
    $timeout = 180
    
    if (!$Cluster){
        Write-Error "No Cluster connected!"

    }elseif (@($isi_sessions | where { $_.cluster -eq $Cluster }).count -eq 0){
        Write-Error "Cluster $Cluster not connected!"
        

    }elseif (((Get-Date) -gt $isi_session.timeout) -or ((Get-Date) -gt $isi_session.timeout_absolute)){
        Write-Error "Session timeout for $Cluster!"
        

    }else{
            try{
                if ($Method -eq 'GET_JSON') {
                    $ISIObject = (Invoke-WebRequest -Uri $url -Method GET -WebSession $session -TimeoutSec $timeout -UseBasicParsing).content

                } elseif ( ($Method -eq 'GET') -or ($Method -eq 'DELETE') ) {
                    $ISIObject = (Invoke-WebRequest -Uri $url -Method $Method -WebSession $session -TimeoutSec $timeout -UseBasicParsing).content | ConvertFrom-Json
                
                } elseif ( ($Method -eq 'PUT') -or ($Method -eq 'POST') ) {
                    $ISIObject = (Invoke-WebRequest -Uri $url -Method $Method -WebSession $session -TimeoutSec $timeout -Body $body -ContentType "application/json; charset=utf-8" -UseBasicParsing).content | ConvertFrom-Json

                }       
            } 
            catch {
                # if it is an Isilon error, extract the error response from http body
                if($_.Exception.PSObject.Properties['Response']){
                    $result = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($result)
                    $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
                    Write-Error $responseBody.errors.message
                } else {
                    Write-Error $_.Exception
                }

            }  
        $isi_session.timeout = (Get-Date).AddSeconds($isi_session.timeout_inactive)
        $ISIObject
    }
}

Export-ModuleMember -Function New-isiSession
Export-ModuleMember -Function Get-isiSession
Export-ModuleMember -Function Get-isiSessionInfo
Export-ModuleMember -Function Get-isiSessionDefault
Export-ModuleMember -Function Set-isiSessionDefault
Export-ModuleMember -Function Remove-isiSession
Export-ModuleMember -Function Send-isiAPI



$moduleRoot = Split-Path -Path $MyInvocation.MyCommand.Path

#GET functions

"$moduleRoot\Functions\*.ps1" | Resolve-Path | ForEach-Object { . $_.ProviderPath }



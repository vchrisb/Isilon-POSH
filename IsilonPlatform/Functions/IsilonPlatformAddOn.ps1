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

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Function Get-isiSmbOpenfilesNode{

<#
.SYNOPSIS
	Get Smb Openfiles from a specific Node

.DESCRIPTION
	List open files from a specific  Node

.PARAMETER Cluster
	Name of Isilon Node

.NOTES

#>
	[CmdletBinding()]
		param (
		[Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True,Position=0)][ValidateNotNullOrEmpty()][string]$Cluster
		)
	Begin{
	}
	Process{

        $token = ''
        # Isilon API limits returned Openfiles to 1000 by default
        $openfiles_node, $token = Get-isiSmbOpenfiles -Cluster $Cluster
        while($token){
            $openfiles_node_resume, $token = Get-isiSmbOpenfiles -resume $token -Cluster $Cluster
            $openfiles_node += $openfiles_node_resume
        }
        $openfiles_node | Add-Member -NotePropertyName Cluster -NotePropertyValue $Cluster
        return $openfiles_node

    }
    End {
    }
}

Export-ModuleMember -Function Get-isiSmbOpenfilesNode
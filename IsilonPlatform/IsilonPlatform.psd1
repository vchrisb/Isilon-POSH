#
# Module manifest for module 'IsilonPlatform'
#
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

@{

# Script module or binary module file associated with this manifest.
RootModule = 'IsilonPlatform.psm1'

# Version number of this module.
ModuleVersion = '8.0.5'

# ID used to uniquely identify this module
GUID = '0bcb10cf-1d7e-4bad-8239-f725dcf1808f'

# Author of this module
Author = 'Christopher Banck'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = '(c) 2016 Christopher Banck. All rights reserved.'

# Description of the functionality provided by this module
Description = 'EMC Isilon Platform API implementation in PowerShell'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('Functions/IsilonPlatformGet.ps1', 'Functions/IsilonPlatformSet.ps1', 'Functions/IsilonPlatformNew.ps1', 'Functions/IsilonPlatformRemove.ps1', 'Functions/IsilonPlatformAddOn.ps1')

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
#CmdletsToExport = '*'

# Variables to export from this module
#VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# HelpInfo URI of this module
HelpInfoURI = 'https://banck.net'

}


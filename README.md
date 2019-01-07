# ADLDSInfo
A PowerShell Script to document Microsoft Active Directory Lightweight Directory Service (AD LDS) Deployments

### DESCRIPTION
A Script which allows you to document an AD LDS Environment.

It will do the following:

* Get a listing of every AD LDS instance in a server, along with status and port numbers
* Collect Server information
* Collect Directory Information
* Collect LDAPs Certificate information
* It can do this for one Node or every replica server.
* Output to command line or HTML report

### Requirements

* Run as Administrator
* PowerShell Remoting (when using -AllNodes). This uses Firewall ports 5985.



### EXAMPLES:

Example 1:  Show all instances in a node and their status

	PS C:\> .\ADLDSInfo.ps1 -ShowInstances

Example 2:  Show information for Instance LFTEST

	PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST

Example 3:  Show information for Instance LFTEST and create an HTML Report

	PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST -HTMLReport

Example 4:  Show information for Instance LFTEST, include all replica nodes, and create an HTML report

	PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST -AllNodes -HTMLReport



### PARAMETERS

-InstanceName <String>
Specifies the InstanceName to get information on.

-WarningsOnly [<SwitchParameter>]
Only return the properties with Warnings.

-ReturnObjectOnly <Boolean>
Returns an unformatted PowerShell Object (for Automation scenarios)


-HTMLReport [<SwitchParameter>]
Writes the report in HTML format.

-SkipExtendedTests [<SwitchParameter>]
Skip the Windows Firewall, Windows Backup and Windows Activation tests.



-SkipServerInfo [<SwitchParameter>]
Skip all system related tests, only display Directory related info.



-AllNodes [<SwitchParameter>]
Process the operation on all Replica nodes.



-ShowInstances [<SwitchParameter>]
Shows all instances in the current node.



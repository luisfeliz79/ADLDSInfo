# ADLDSInfo

### DESCRIPTION
A PowerShell Script to document Microsoft Active Directory Lightweight Directory Service (AD LDS) Deployments

It can do the following:

* Get a listing of every AD LDS instance in a server, along with status and port numbers
* Collect Server information
* Collect Directory Information
* Collect LDAPs Certificate information
* Output to command line or HTML report

### Requirements

* Run as Administrator
* PowerShell Remoting (when using -AllNodes). PS Remoting uses firewall port 5985.



### EXAMPLES:

Example 1:  Show all instances in a node and their status

	PS C:\> .\ADLDSInfo.ps1 -ShowInstances

Example 2:  Show information for Instance LFTEST

	PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST

Example 3:  Show information for Instance LFTEST and create an HTML Report

	PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST -HTMLReport



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



-ShowInstances [<SwitchParameter>]
Shows all instances in the current node.

### Sample Screenshots

![](https://github.com/luisfeliz79/ADLDSInfo/blob/master/ScreenShots/ShowInstances.PNG)
![](https://github.com/luisfeliz79/ADLDSInfo/blob/master/ScreenShots/CommandLineReport.png)
![](https://github.com/luisfeliz79/ADLDSInfo/blob/master/ScreenShots/HTMLReport.png)


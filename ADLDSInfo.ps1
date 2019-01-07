#requires -version 4

<#

.SYNOPSIS

  AD LDS Documenter



.DESCRIPTION

  A Script which allows you to document an AD LDS Environment.

  It will do the following:
  
        * Get a listing of every AD LDS instance in a server, along with status and port numbers
        * Collect Server information
        * Collect Directory Information
        * Collect LDAPs Certificate information
        * It can do this for one Node or every replica server.
        * Output to command line or HTML report

    EXAMPLES:

    Example 1:  Show all instances in a node and their status

      PS C:\> .\ADLDSInfo.ps1 -ShowInstances

    Example 2:  Show information for Instance LFTEST

      PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST
    
    Example 3:  Show information for Instance LFTEST and create an HTML Report

      PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST -HTMLReport

    Example 4:  Show information for Instance LFTEST, include all replica nodes, and create an HTML report

      PS C:\> .\ADLDSInfo.ps1 -InstanceName LFTEST -AllNodes -HTMLReport


.PARAMETER InstanceName

  Specifies the InstanceName to get information on.

.PARAMETER ShowInstances

  Shows all instances in the current node.

.PARAMETER AllNodes

  Process the operation on all Replica nodes.

.PARAMETER HTMLReport

  Writes the report in HTML format.

.PARAMETER WarningsOnly

  Only return the properties with Warnings.

.PARAMETER SkipExtendedTests

  Skip the Windows Firewall, Windows Backup and Windows Activation tests.

.PARAMETER SkipServerInfo

  Skip all system related tests, only display Directory related info.

.PARAMETER ReturnObjectOnly

  Returns an unformatted PowerShell Object (for Automation scenarios)


  
.NOTES

  Version:        1.0.4

  Author:         Luis Feliz

  Creation Date:  1/7/2019

  Purpose/Change: Initial script development
  

#>



[CmdletBinding()]
    param (
        [String]$InstanceName,
        [Switch]$WarningsOnly,
        [Boolean]$ReturnObjectOnly,
        [Switch]$HTMLReport,
        [Switch]$SkipExtendedTests,
        [Switch]$SkipServerInfo,
        [Switch]$AllNodes,
        [Switch]$ShowInstances
        
    )


# CHANGES
# Fixed a bug that removed backslashes from path names. affected the -HTMLReport function.

#region User Defined variables
 $UpdateCheck=60
 $FreeSpaceCheck=5
 $FWRuleWarn=$true
 $BackupJobWarn=$True

#endregion

#region Program Variables

$ScriptVersion="1.0.4"
$global:Report=@() #Define an array 
$global:RemoteReports=@{} #Define a hash table



#endregion


#region helper modules

#User right assignments code borrowed from Tony's PowerShell Module
#Get the complete module here https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0
Add-Type -TypeDefinition @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,             // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                         // Access this computer from the network
        SeTcbPrivilege,                              // Act as part of the operating system
        SeMachineAccountPrivilege,                   // Add workstations to domain
        SeIncreaseQuotaPrivilege,                    // Adjust memory quotas for a process
        SeInteractiveLogonRight,                     // Allow log on locally
        SeRemoteInteractiveLogonRight,               // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                           // Back up files and directories
        SeChangeNotifyPrivilege,                     // Bypass traverse checking
        SeSystemtimePrivilege,                       // Change the system time
        SeTimeZonePrivilege,                         // Change the time zone
        SeCreatePagefilePrivilege,                   // Create a pagefile
        SeCreateTokenPrivilege,                      // Create a token object
        SeCreateGlobalPrivilege,                     // Create global objects
        SeCreatePermanentPrivilege,                  // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,               // Create symbolic links
        SeDebugPrivilege,                            // Debug programs
        SeDenyNetworkLogonRight,                     // Deny access this computer from the network
        SeDenyBatchLogonRight,                       // Deny log on as a batch job
        SeDenyServiceLogonRight,                     // Deny log on as a service
        SeDenyInteractiveLogonRight,                 // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,           // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,                 // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,                   // Force shutdown from a remote system
        SeAuditPrivilege,                            // Generate security audits
        SeImpersonatePrivilege,                      // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,               // Increase a process working set
        SeIncreaseBasePriorityPrivilege,             // Increase scheduling priority
        SeLoadDriverPrivilege,                       // Load and unload device drivers
        SeLockMemoryPrivilege,                       // Lock pages in memory
        SeBatchLogonRight,                           // Log on as a batch job
        SeServiceLogonRight,                         // Log on as a service
        SeSecurityPrivilege,                         // Manage auditing and security log
        SeRelabelPrivilege,                          // Modify an object label
        SeSystemEnvironmentPrivilege,                // Modify firmware environment values
        SeDelegateSessionUserImpersonatePrivilege,   // Obtain an impersonation token for another user in the same session
        SeManageVolumePrivilege,                     // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,             // Profile single process
        SeSystemProfilePrivilege,                    // Profile system performance
        SeUnsolicitedInputPrivilege,                 // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                           // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,               // Replace a process level token
        SeRestorePrivilege,                          // Restore files and directories
        SeShutdownPrivilege,                         // Shut down the system
        SeSyncAgentPrivilege,                        // Synchronize directory service data
        SeTakeOwnershipPrivilege                     // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );


        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

   
        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

       
        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

      

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }


}
'@ # This type (PS_LSA) is used by Get-UserRightsGrantedToAccount

function Get-UserRightsGrantedToAccount {

    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username','SID')][String[]] $Account,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            $rights = $lsa.EnumerateAccountPrivileges($Acct)
            foreach ($right in $rights) {
                $output = @{'Account'=$Acct; 'Right'=$right; }
                Write-Output (New-Object -Typename PSObject -Prop $output)
            }
        }
    }
} # Gets all user rights granted to an account


function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
} # Test if current shell is Running As Administrator 

Function WriteOutput ($header,$output,$notes) {

    if ($notes) {$Notes = "WARNING: $Notes`n"}

   $global:Report+= New-Object PSobject -Property ([ordered]@{

    "Property"=$header
    "Value"=$Output
    "Notes"=$Notes

    })
    

    write-progress -activity "Examining $env:ComputerName - $InstanceName" -Status "Completed: $Header"

} # handles the creation of report object

Function WriteError ($Output) {

   Write-Host "$($env:computername): $Output" -ForegroundColor Red

} # handles writing errors to the screen

Function RunTest ($TestName,$InstanceName) {

Switch ($TestName)  
{ 

"SysInfo" {
          #System Information
          $RAM=(Get-WmiObject -class "Win32_PhysicalMemory").Capacity/1024/1024/1024
          $CPU=get-wmiobject win32_processor
          $OS=(Get-WmiObject Win32_OperatingSystem)
          $Uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
          $LastUpdate= (gwmi win32_quickfixengineering |sort installedon -desc).InstalledON[0]
          $LastUpdateNotes=if ($LastUpdate -le (get-date).AddDays($UpdateCheck*-1)) {"Last update was more than $UpdateCheck days ago"}
          $HDInfo = get-WmiObject win32_logicaldisk 
          $FreeSpace=$($HDInfo | % {"$($_.DeviceID) $([math]::round($_.FreeSpace/1024/1024/1024,1))GB" } ) -join "`n"
          $FreeSpaceNotes=if (($HDInfo | % {if ("[math]::round($_.FreeSpace/1024/1024/1024,1)" -le $FreeSpaceCheck) {$true} } )) {"Some drives have less than $($FreeSpaceCheck)GB"}
          
          Writeoutput -header InstanceName -Output $InstanceName
          writeoutput -header HostName -Output $([System.Net.Dns]::GetHostByName($env:computerName).hostname)
          writeoutput -header IPaddress -output ([System.Net.Dns]::GetHostByName($env:computerName).AddressList) -join ", "
          writeoutput -header SystemOS -Output $OS.Caption
          WriteOutput -header SystemCPU -Output "$($CPU.name) / $($CPU.NumberOfEnabledCore) enabled cores out of $($CPU.NumberOfCores) / $($CPU.NumberOfLogicalProcessors) Logical"
          WriteOutput -header SystemMemory -output "$RAM GB"
          writeoutput -header FreeSpace -Output $FreeSpace -notes $FreeSpaceNotes
          Writeoutput -header SystemUptime -output "$($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes"
          writeoutput -header LastUpdated -output $LastUpdate -notes $LastUpdateNotes
          
          

} # Collects basic system info

"ADLDS" {
        #AD LDS Specific info

       $ConfigParameters=get-item "HKLM:\SYSTEM\CurrentControlSet\Services\ADAM_$InstanceName\Parameters"
       $PortLDAP=$ConfigParameters.getvalue("Port LDAP")
       $PortSSL=$ConfigParameters.getvalue("Port SSL")
       $DSADBPath=$ConfigParameters.getvalue("DSA Working Directory")
       $LogDBPath=$ConfigParameters.getvalue("Database log files path")
       $Service=Get-WmiObject -Class win32_service | where name -eq  ADAM_$InstanceName
       $ServiceState=$Service.State
       $ServiceStateNote=if ($ServiceState -eq "Running") {} else {"Service is not running"}
       $ServiceAccount=$Service.StartName
       $ServiceAccountNotes="LocalSystem","NT Authority","NT Service",".\" | foreach {if ($ServiceAccount -like "*$_*"){ "This does not appear to be a domain account."}}
       $ADWSService=get-service adws
       $ADWSServiceState=$ADWSService.Status 
       $ADWSServiceStateNote=if ($ADWSServiceState -eq "Running") {} else {"Service is not running"}


       try {
       $AuditingEnabled = if ((Get-UserRightsGrantedToAccount -Account $($ServiceAccount -replace '\.\\',"")).Right -contains "SeAuditPrivilege") {$True} else {$false}
       }
       Catch { $AuditingEnabled = "Error getting auditing privileges information"}
   
       $AuditingEnabledNotes = if ($AuditingEnabled -eq $false) {"Service account $Serviceaccount is not listed under the 'Generate security audits' user right assignment. This may be ok if the account inherits permissions via a nested group. "} 
       $PasswordPolicy=(net accounts | where { $_ -like "*:*" } ) -replace "  ","" -join "`n"
  
       WriteOutput -Header AuditingEnabled -Output $AuditingEnabled -notes $AuditingEnabledNotes
       WriteOutput -Header ServiceAccount -Output $ServiceAccount -notes $ServiceAccountNotes
       WriteOutput -Header ServiceState -Output $ServiceState -notes $ServiceStateNote
       WriteOutput -Header ADWSServiceState -Output $ADWSServiceState -notes $ADWSServiceStateNote
       WriteOutput -Header PasswordPolicy -Output $PasswordPolicy
       WriteOutput -Header PortLDAP -Output $PortLDAP
       WriteOutput -Header PortSSL -Output $PortSSL
       WriteOutput -Header DSADBPath -Output $DSADBPath
       WriteOutput -Header LogDBPath -Output $LogDBPath
  
       #LDAPS INFO
       $tmpLDAPSCert=invoke-expression "certutil -store -service -service ADAM_$instanceName\my"
       $tmpLDAPSCertV=invoke-expression "certutil -store -v -service -service ADAM_$instanceName\my"
  
        if (($tmpLDAPSCert -join " ") -notlike "*failed*") {
                $LDAPSCertSubject=($tmpLDAPSCert | select-string -Pattern "Subject: ") -replace "Subject: " 
                $LDAPSCertSubjectNotes=if ($LDAPSCertSubject.count -gt 1) {"There are more than 1 certificates installed on the Service account store. There should only be one."}
                $LDAPSCertSAN=($tmpLDAPSCertV | select-string -Pattern "DNS Name") -replace "DNS Name=","" -replace " ","" -join ", "
                $LDAPSCertExpiration=($tmpLDAPSCert | select-string -Pattern "NotAfter: ") -replace "NotAfter:","" -replace "  ",""
                $LDAPSCertExpirationNotes=if ($LDAPSCertExpiration -le (Get-Date)) { "The Certificate is expired!" }
                $LDAPSCertThumbPrint=($tmpLDAPSCert | select-string -Pattern "Cert Hash")[0] -replace "Cert Hash","" -replace ":","" -replace " ",""
                $LDAPSPrivateKeySec=$($tmpLDAPSCertV | select-string -Pattern " Allow ") -replace "  ","" -join "`n"
                $LDAPSPrivateKeySec=$LDAPSPrivateKeySec.trim()
                $LDAPSPrivateKeySecNotes=if ($LDAPSPrivateKeySec -notlike "*$ServiceAccount*") { "Ensure account $serviceaccount has access to the private keys via a nested group or direct assignment."}

                WriteOutput -Header LDAPSCertExpiration -Output $LDAPSCertExpiration -notes $LDAPSCertExpirationNotes
                WriteOutput -Header LDAPSCertSAN -Output $LDAPSCertSAN -notes $LDAPSCertSubjectNotes
            
                WriteOutput -Header LDAPSCertSubject -Output $LDAPSCertSubject
                WriteOutput -Header LDAPSCertThumbPrint -Output $LDAPSCertThumbPrint
                WriteOutput -Header LDAPSPrivateKeySec -Output $LDAPSPrivateKeySec -notes $LDAPSPrivateKeySecNotes
  
        } else { WriteOutput -Header "LDAPSCert" -output "No Certificate Found" }

        #If the instance is running, connect to it and grab info.

       if ($ServiceState -eq "Running" -and $ADWSServiceState -eq "Running") {
   
            $path=[adsi]"LDAP://localhost:$PortLDAP/RootDSE"
            $ConfigPart=$path.configurationNamingContext
            $AppParts=$path.namingContexts | where { $_ -notlike "*CN=Configuration*" }
            
            #Check if login account has permissions
            $SecCheck=[adsi]"LDAP://localhost:$PortLDAP/$ConfigPart"
            if ($secCheck.path -ne $null) {
                        
        
                $tmpPartData=get-adobject -server localhost:$PortLDAP -Identity "CN=Partitions,$($ConfigPart)" -Properties msDS-Behavior-Version,msDS-EnabledFeature,fSMORoleOwner
      
                    $FuncLevel=$tmpPartData.'msDS-Behavior-Version'
                    $RecycleBinEnabled=if ($tmpPartData.'msDS-EnabledFeature' -like "*Recycle*") {$true} else {$false}
                    $RecycleBinEnabledNotes=if ($RecycleBinEnabled -eq $false) {"The Recycle bin is not enabled, see https://docs.microsoft.com/en-us/powershell/module/activedirectory/enable-adoptionalfeature?view=winserver2012-ps"}
                    $NamingMaster=((($tmpPartData.'fSMORoleOwner') -split ",")[1] -split "\$" -Replace "CN=","")[0]
        
                $tmpPartData=get-adobject -server localhost:$PortLDAP -Filter {ObjectClass -eq "server"}  -SearchBase "CN=Sites,$($ConfigPart)" -Properties DnsHostName
        
                    $ReplicaPartners=$tmpPartData.DnsHostName -join ", "
        
                $tmpPartData=get-adobject -server localhost:$PortLDAP -Filter {ObjectClass -eq "site"}  -SearchBase "CN=Sites,$($ConfigPart)"
                
                    $Sites=$tmpPartData.Name -join ", "

                $tmpPartData=get-adobject -server localhost:$PortLDAP -Filter {ObjectClass -eq "siteLink"}  -SearchBase "CN=IP,CN=Inter-Site Transports,CN=Sites,$($ConfigPart)" -Properties Options,SiteList
                    $SiteLinkList=@()    
                    $SiteLinks=($tmpPartData | foreach {
                
                        $SiteLinkName=$_.Name
                        $SiteLinkList=($_.SiteList | foreach {($_ -split "CN=")[1] -replace ",","" }) -join " / "
                
                        switch ($_.options) {

                        1 {$SiteLinkOptions= "[USE_NOTIFY]"}
                        2 {$SiteLinkOptions= "[TWOWAY_SYNC]"}
                        3 {$SiteLinkOptions= "[USE_NOTIFY | TWOWAY_SYNC]"}
                        4 {$SiteLinkOptions= "[DISABLE_COMPRESSION]"}
                        5 {$SiteLinkOptions= "[USE_NOTIFY | DISABLE_COMPRESSION]"}
                        6 {$SiteLinkOptions= "[TWOWAY_SYNC | DISABLE_COMPRESSION]"}
                        7 {$SiteLinkOptions= "[USE_NOTIFY | TWOWAY_SYNC | DISABLE_COMPRESSION]"}
                        default {$SiteLinkOptions= "[No Options]"}

                        }
                
                        "$($SiteLinkName): $SiteLinkList $SiteLinkOptions"
                    }) -join "`n"

            


                $tmpPartData=get-adobject -server localhost:$PortLDAP -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($ConfigPart)" -Properties "msDS-Other-Settings"

                    $msDSOtherSettings=$tmpPartData.'msDS-Other-Settings' -join ", "
        
                $tmpPartData=get-adobject -server localhost:$PortLDAP -Identity "CN=Schema,$($ConfigPart)" -Properties fSMORoleOwner
        
                    $SchemaMaster=((($tmpPartData.'fSMORoleOwner') -split ",")[1] -split "\$" -Replace "CN=","")[0]
  
                        try{
	                    $Administrators=(Get-ADGroupMember -server localhost:$PortLDAP -Identity "CN=Administrators,CN=Roles,$($ConfigPart)").distinguishedName
	                    }
	                    Catch {
	                    $Administrators="Error getting group membership"
	                    }

            WriteOutput -Header Administrators -Output $Administrators
            WriteOutput -Header AppParts -Output $AppParts
            WriteOutput -Header ConfigPart -Output $ConfigPart
            WriteOutput -Header FuncLevel -Output $FuncLevel
            WriteOutput -Header NamingMaster -Output $NamingMaster
            WriteOutput -Header RecycleBinEnabled -Output $RecycleBinEnabled -notes $RecycleBinEnabledNotes
            WriteOutput -Header ReplicaPartners -Output $ReplicaPartners
            WriteOutput -Header SchemaMaster -Output $SchemaMaster
            WriteOutput -Header Sites -Output $Sites
            WriteOutput -Header SiteLinks -output $SiteLinks
            writeoutput -Header msDSOtherSettings -output $msDSOtherSettings
        } else { WriteError -Output "Your login account does not have administrative access to this AD LDS instance, skipping directory tests." }

   } else {
    WriteError -Output "Either the $InstanceName service or the ADWS Service is not running, skipping Directory tests.   Start the services and re-run the script."
   }

} # Performs the Directory tests

"SystemExtended" {

    #Will check Firewall, BackupSoftware and KMS activation

    $FWcheck=Get-NetFirewallProfile | select Enabled
    if ($fwcheck) {
        $FirewallEnabled=$true
        $FWRulesCheck=Get-NetFirewallRule | where DisplayName -like *LeastPriv*
        if ($FwRulesCheck.count -eq 0 -and $FWRuleWarn) {$FirewallEnabledNotes="The firewall is enabled, but the appropiate rules may not be in place for this AD LDS Instance."} 
    } else {$FirewallEnabled=$False}
    
    $WBCheck=get-windowsfeature Windows-Server-Backup
    if ($WBCheck.InstallState -eq "Installed") {
        $WSBackupInstalled=$True
        $WBJobCheck=Get-WBSummary
        if ($WBJobCheck.NextBackupTime -lt (get-date) -and $BackupJobWarn) {
            $WSBackupInstalledNotes="There is no backup scheduled on this server"
        }
    }
    $ActivationCheck=get-wmiObject -query  "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey <> null AND ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseIsAddon=False"| select Description,LicenseStatus
    if ($ActivationCheck.LicenseStatus -eq 1) {$OSActivated="$true"} else {
        $OSActivated=$false
        $OSActivatedNotes="Windows is not activated - $($ActivationCheck.Description) - $($ActivationCheck.LicenseStatus)"
    }

     WriteOutput -Header FirewallEnabled -Output $FirewallEnabled -notes $FirewallEnabledNotes
     WriteOutput -Header WSBackupInstalled -Output $WSBackupInstalled -notes $WSBackupInstalledNotes
     WriteOutput -Header OSActivated -Output $OSActivated -notes $OSActivatedNotes
              

} # Performs Firewall,Activation,Backup tests

Default {writeoutput "Error" "No test was specified"}

}

} # Performs the tests

Function ShowAvailableInstances () {
$Results=@()
$Instances=Get-WmiObject -Class win32_service | where name -like ADAM_*
$Instances | foreach {

   $ConfigParameters=get-item "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\Parameters"
   $PortLDAP=$ConfigParameters.getvalue("Port LDAP")
   $PortLDAPS=$ConfigParameters.getvalue("Port SSL")

    $Results+=New-Object PSobject -Property ([ordered]@{

    "Status"=$_.State
    "Name"=$_.Name
    "DisplayName"=$_.DisplayName
    "LDAPPort"=$PortLDAP
    "LDAPSPort"=$PortLDAPS
    "ServiceAccount"=$_.StartName

    }) 

}
    $results | ft

} # Provides a nice listing of all the instances

Function CheckRequirements () {

# Test if current shell is Running As Administrator 
if (-not (Test-Administrator)) { WriteError -output "This script requires to be run as an Administrator.";exit }


$ADToolsCheck=get-windowsfeature RSAT-AD-PowerShell
    if ($ADToolsCheck.InstallState -ne "Installed") {
       WriteError -Output "This script requires the AD PowerShell Tools.  Please install using  Intall-Windowsfeature RSAT-AD-PowerShell";exit
    }

} # Does some basic checks

Function CreateHTMLReport () {

    #Define templates

    $Title="AD LDS Configuration report"
    $Subtitle="Script Version $ScriptVersion"

    $Style=@" 
    <style>
    table {border: 0px solid black ; padding:15px;font-family: Verdana, Geneva, sans-serif;font-size:16px;}
    th,td {border: 1px solid black; padding:15px;vertical-align:top;}
    th {background-color: #4CAF50; color: white;align:left;}
    tr:nth-child(even) {background-color: #f2f2f2}
    .titlerow { font-weight:bold;   }
    .warning { background-color:LightCoral;border:0px;padding:5px;}
    .warningrow {border: 0px; padding:5px;}
    .title { font-family: Verdana, Geneva, sans-serif;font-size:30px }
    .subtitle { font-family: Verdana, Geneva, sans-serif;color:gray;font-size:10px; }
    .datarow {}
    </style>
"@


    # Create the header

    $Header="<HTML><Head><Title>AD LDS Info Report - $(get-date)</title>$style</head><body><p class=Title>$Title</p><p class=Subtitle>$Subtitle</p>"
    
    # Create the System info area

        if (-not $SkipServerInfo) {

        $Modules="HostName","IPAddress","SystemOS","SystemCPU","SystemMemory","FreeSpace","SystemUptime","LastUpdated","PasswordPolicy"
        if (-not $SkipExtendedTests) { $modules+="FirewallEnabled","OSActivated","WSBackupInstalled"}

        $AreaTitle="@System Info"
        $SystemArea=CreateHTMLReportArea -Modules $Modules -Title $AreaTitle -Multi
        }
    # Create the Basic Directory info area

        $Modules="HostName","InstanceName","Administrators","ADWSServiceState","AppParts","ConfigPart","DSADBPath","LogDBPath","NamingMaster","PortLDAP","PortSSL","SchemaMaster","ServiceAccount","ServiceState"
        $AreaTitle="@Instance Information"
        $DirectoryArea=CreateHTMLReportArea -Modules $Modules -Title $AreaTitle 

    # Create the Certificates area

        $Modules="HostName","LDAPSCertExpiration","LDAPSCertSAN","LDAPSCertSubject","LDAPSCertThumbPrint","LDAPSPrivateKeySec"
        $AreaTitle="@LDAPs Configuration"
        $CertificatesArea=CreateHTMLReportArea -Modules $Modules -Title $AreaTitle -Multi
    
    # Create Replication area

        $Modules="HostName","ReplicaPartners","SiteLinks","Sites"
        $AreaTitle="@Replication Configuration"
        $ReplicationArea=CreateHTMLReportArea -Modules $Modules -Title $AreaTitle
    
      
    # Create the Options and Features area

        $Modules="HostName","FuncLevel","RecycleBinEnabled","msDSOtherSettings"
        $AreaTitle="@Options and Features"
        $OptFeatureArea=CreateHTMLReportArea -Modules $Modules -Title $AreaTitle
    
    # Create the footer 
    $Footer="</body></html>"

    # Export to a file

    $HtmlReport="$header $SystemArea $CertificatesArea $DirectoryArea $ReplicationArea $OptFeatureArea $Footer"
    
    if ($pwd.tostring()[-1] -eq "\") {$Curdir=$PWD} else {$CurDir="$pwd\"}
    
    $HtmlreportFile="$CurDir$env:computername-$InstanceName-$(get-date -format 'MMddyyyy-hhmm').html"
    $HtmlReport | out-file $HtmlreportFile
    "Report created at $HtmlreportFile"
}

function CreateHTMLReportArea ($Modules, $Title,[switch]$Multi) {

if ($Title -like "@*") { $TitleText=$Title -replace "@","" } else {
    $TitleText=($global:Report | where Property -eq $Title).Value
}
$HTML="<TABLE class=SectionTable><TR class=Section><Th class=TitleRow>$TitleText</th></tr>"

foreach ($prop in $Modules) {
    
    $HTML+="<TR class=Section><TD class=DataRow>$($Prop)</td>"  

    $global:RemoteReports.keys | foreach {
    
    $PropData=($global:RemoteReports[$_] | where Property -eq $prop)
    $HTML+="  <TD class=DataRow>$($PropData.Value -replace "`n","<br>" -replace ", ","<BR>")"
    if ($PropData.Notes) { $HTML+="<table class=Warning><tr><TD class=warningrow>$($PropData.Notes)</td></tr></table></td>" } else {$HTML+="</td>"}
    
    } # go through each node
    $HTML+="</tr>"
    } # go thorugh all properties


$HTML+="</TABLE><br>"

$HTML

}


#endregion


#region Begin Main section





CheckRequirements

if ($ShowInstances) {
"Available Instances:";ShowAvailableInstances;break
}

if ($InstanceName) {

    #Normalize Instance Names
    if ($InstanceName -notlike "ADAM_*") {$InstanceFullName = "ADAM_$InstanceName"} else {$InstanceFullName=$InstanceName}
    $InstanceShortName=$InstanceName -replace "ADAM_",""


     try {
        #Check the instance name against registry configuration
        $NameCheck=get-item "HKLM:\SYSTEM\CurrentControlSet\Services\$InstanceFullName\Parameters" -ErrorAction stop

        } catch {

        Writeerror -Output "Could not find instance $InstanceName. See available instances:"
        ShowAvailableInstances
        exit

        }

        #Run the tests
        if (-not $SkipServerInfo)    { RunTest -TestName sysinfo -InstanceName $InstanceShortName}
        if (-not $SkipExtendedTests -and -not $SkipServerInfo) { RunTest -TestName SystemExtended -InstanceName $InstanceShortName}   
        
        RunTest -TestName adlds -InstanceName $InstanceShortName
        WriteOutput -header ScriptVersion -output $ScriptVersion   

 } else { "Please specify an instance name with -InstanceName name. For more help use -?";ShowAvailableInstances;break}

 #Display the report
 
    #Ensures that column data is not trucated
    $FormatEnumerationLimit=0
   
    #Adds the local report to RemoteReports
        $RemoteReports.add([System.Net.Dns]::GetHostByName($env:computerName).hostname,$Report)
   
    #Includes data from all ReplicaPartners
    if ($AllNodes) {

    
    
    $ThisScript=$MyInvocation.MyCommand.source
    [System.Collections.ArrayList]$Nodes=($Report | where Property -eq "ReplicaPartners").value -split ", "
    $Nodes.remove([System.Net.Dns]::GetHostByName($env:computerName).hostname)


        $Nodes | foreach {
        if ($_) {  
        $RemoteReports.add($_,(Invoke-Command -computername $_ -FilePath $ThisScript -ArgumentList $InstanceName,$true))
        }
        }
     
    }

    #an option to only show rows with warnings
    If ($WarningsOnly) {

        if ($HTMLReport) {write-host "Ignoring -HTMLReport, these two switches cannot be used together" -ForegroundColor Yellow}
       
            $RemoteReports.keys | foreach {"Report for $_`n-----------------------------";$RemoteReports[$_] | where Notes -ne $null | fl Property,Value,Notes}
        
    Break
    }
    
    #use this to get an unmodified powershell object out of the script
    If ($ReturnObjectOnly) {
        return $Report
    break
    }
    
    #creates a pretty html based report
    If ($HtmlReport) {
        CreateHTMLReport
    Break
    }


    #default action
    #$Report  | ft -Property @{label="Property";Expression={$_.Property};Width=20;Alignment="Left"},@{label="Value";Expression={$_.Value};Width=80;Alignment="Left"},@{label="Notes";Expression={$_.Notes};Width=40;Alignment="Left"} -wrap
    $RemoteReports.keys | foreach {$RemoteReports[$_] | ft -Property @{label="Property";Expression={$_.Property};Width=20;Alignment="Left"},@{label="Value";Expression={$_.Value};Width=80;Alignment="Left"},@{label="Notes";Expression={$_.Notes};Width=40;Alignment="Left"} -wrap }
    
#endregion

#Global variables
#Log Analytics Agent Tool
[string]$global:AgentRootKey = "SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Service Connector Services"

$ErrorActionPreference = "SilentlyContinue"

[bool]$global:TLSv1_0 = $true
[bool]$global:TLSv1_1 = $true
[bool]$global:TLSv1_2 = $true
[bool]$global:success = $true

#AMA Agent Tool
[string]$global:onPremRegPath = "HKLM:\SOFTWARE\Microsoft\AzureMonitorAgent"
[string]$global:Ama1PModeDataStoreDir = "AMA_MT_DataStore*";
[string]$global:vmDir = "C:\WindowsAzure\Resources\"
[string]$global:arcDir = "C:\Resources\Directory"

#Menus
function Show-Menu
{
    Clear-Host
    Write-Host "================ Please select agent to troubleshoot ================"
    Write-Host 
    Write-Host "1: Azure Connected Machine Agent(ARC)"
    Write-Host "2: Azure Monitoring Agent"
    Write-Host "3: Azure Log Analytics Agent"
    #Write-Host "4: Hybrid worker"
    Write-Host "============================================================================================"
}

function Show-SubMenu
{
    Write-Host "========== Please select the action that you would like to perform =========="
    Write-Host "1: Check agent status"
    Write-Host "2: Check connectivity to endpoints"
    Write-Host "============================================================================="
    $selection = Read-Host "Please select an option: "
    return $selection
}

#Main
function main
{
    Show-Menu    

    $selection = Read-Host "Please select an option"
    switch ($selection)
    {
        '1' 
        {
            Write-Host 'You selected option #1' -ForegroundColor DarkGreen -BackgroundColor White
            CheckAzureConnectedMachineAgentConnectivity
        }
        '2'
        {
            Write-Host 'You selected option #2' -ForegroundColor DarkGreen -BackgroundColor White
            CheckAMAConnectivity
        }
        '3'
        {
            Write-Host 'You selected option #3' -ForegroundColor DarkGreen -BackgroundColor White
            CheckMMAConnectivity
        }
        #'4'
        #{
            #Write-Host 'You selected option #4' -ForegroundColor DarkGreen -BackgroundColor White
            #CheckHybridWorkerConnectivity
        #}
        'q' 
        {
            return
        }
        'Q'
        {
            return
        }
        default 
        {
            'No option selected'
        }
    }
}

#Main Agent Functions
function CheckAMAConnectivity
{
    $selection = Show-SubMenu
    switch ($selection)
    {
        '1' 
        {
            Write-Host 'You selected option #1' -ForegroundColor DarkGreen -BackgroundColor White 
            CheckAMAStatus
        }
        '2' 
        {
            Write-Host 'You selected option #2' -ForegroundColor DarkGreen -BackgroundColor White
            CheckAMAEndpointsConnectivity
        }
        default 
        {
            'No option selected'
        }
    }
}

function CheckMMAConnectivity
{
    $selection = Show-SubMenu
    switch ($selection)
    {
        '1' 
        {
            Write-Host 'You selected option #1' -ForegroundColor DarkGreen -BackgroundColor White
            CheckMMAStatus
        }
        '2' 
        {
            Write-Host 'You selected option #2' -ForegroundColor DarkGreen -BackgroundColor White
            CheckMMAEndpointsConnectivity
        }
        default 
        {
            'No option selected'
        }
    }
}

function CheckAzureConnectedMachineAgentConnectivity
{
    $selection = Show-SubMenu
    switch ($selection)
    {
        '1' 
        {
            Write-Host 'You selected option #1' -ForegroundColor DarkGreen -BackgroundColor White
            CheckARCStatus
        }
        '2' 
        {
            Write-Host 'You selected option #2' -ForegroundColor DarkGreen -BackgroundColor White
            CheckARCEndpointsConnectivity
        }
        default 
        {
            'No option selected'
        }
    }
}

function CheckHybridWorkerConnectivity
{
    $selection = Show-SubMenu
    switch ($selection)
    {
        '1' 
        {
            Write-Host 'You selected option #1' -ForegroundColor DarkGreen -BackgroundColor White
            CheckHWStatus
        }
        '2' 
        {
            Write-Host 'You selected option #2' -ForegroundColor DarkGreen -BackgroundColor White
            CheckHWEndpointsConnectivity
        }
        default 
        {
            'No option selected'
        }
    }
}

#Subfunctions
#Common
function GetServiceStatus([string]$service)
{
    return (Get-Service -Name $service).Status
}
#ARC agent Common
function GetARCInstanceInfo 
{
    $azureInstanceInfoJson = (Get-Content "C:\ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json" | ConvertTo-Json | ConvertFrom-Json).value
    return $azureInstanceInfoJson | ConvertFrom-Json
}

#MMA Common
function CheckIfMMACertPresent
{
    Write-Host "Checking if Log Analytics certificate is present on the machine."

    [bool]$present = $true
    try
    {
        $key = "hklm:\"+$global:AgentRootKey
        $hive = @(Get-ChildItem $key -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*\Log Analytics*$workspaceId*"})[0]
        $obj2 = Get-ItemProperty -Path $hive.PSPath -Name "Authentication Certificate Thumbprint" | Select-Object "Authentication Certificate Thumbprint"
        if($null -ne $obj2)
        {
            $certThumbprint = $obj2.'Authentication Certificate Thumbprint'
        }

        $result = Get-ChildItem -Path "Cert:\LocalMachine" -Recurse | Where-Object {$_.Thumbprint -eq $certThumbprint}
        if($null -eq $result)
        {
            Write-Host "MMA certificate is not present on the machine."
            $present = $false
        }
    }
    catch 
    {
        Write-Error "Caught exception: $($_.Exception.Message)"
        $present = $false
    }

    Write-Host "MMA certificate check complete."
    return $present
}
function RunCloudConnectionTool
{
    $cloudConnectionToolPath = "C:\Program Files\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe"
    [string]$toolOutput = & "$cloudConnectionToolPath"
    [bool]$success2 = $false

    Write-Host "Running cloud connection tool."

    if([string]::IsNullorEmpty($toolOutput))
    {
        Write-Host "Unable to run cloud collection tool"
        return $success2
    }

    switch -regex ($toolOutput)
    {
        'Connectivity test passed for .+' 
        {
            # cloudconection tool passed
            $success2 = $true
        }

        'Proxy setting .+ is not a valid URL'        
        {
        }

        '.+ request did not complete .+'
        {
        }

        '.+ firewall may be blocking .+'
        {
        }

        'proxy settings failed'
        {
        }

        '.+ failed .+'
        {
        }

        'certificate .+ is invalid due to .+'
        {
            # log certificate issue
        }
        default
        {
            
        }
    }

    if($false -eq $success2)
    {
        Write-Host "TestCloudConnection.exe has reported errors. Please fix."
        Write-Host "More details available here: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/agent-windows-troubleshoot#connectivity-issues "
    }
    else
    {
        Write-Host "Tool ran successfully."
    }

    return $success2
}
function TestConnectivityToLAEndpoints
{
    try
    {
        Write-Host "Starting connectivity test for Log Analytics endpoints..."

        $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $subKey = $regKey.OpenSubKey($global:AgentRootKey)
        $subKey.GetSubKeyNames() | foreach-object {
            $workspaceKey = $regKey.OpenSubKey($global:AgentRootKey + "\" + $_)
            $url = $workspaceKey.GetValue("Topology Request Url")
            $url -match "https://(?<content>.*)/AgentService.svc/AgentTopologyRequest" >$null

            $omsEndpoint = $matches['content']
            $allLogAnalyticsEndpoints = New-Object System.Collections.ArrayList
            $allLogAnalyticsEndpoints.Add($omsEndpoint)

            $pos = $omsEndpoint.IndexOf(".")
            $workspaceId = $omsEndpoint.Substring(0, $pos)
            $allLogAnalyticsEndpoints.Add($workspaceId+".ods.opinsights.azure.com")
            $allLogAnalyticsEndpoints.Add($workspaceId+".agentsvc.azure-automation.net")
            $allLogAnalyticsEndpoints.Add("scadvisorcontent.blob.core.windows.net")
            $allLogAnalyticsEndpoints.Add("swin.his.arc.azure.com")

            foreach($endpoint in $allLogAnalyticsEndpoints)
            {      
                try 
                {
                    Write-Host "Testing secure connection to: $endpoint" -ForegroundColor DarkGreen -BackgroundColor White           
                    
                    $hostObject = New-Object psobject -Property @{
                        Host = $endpoint
                        Port = 443
                        SSLv2 = $false
                        SSLv3 = $false
                        TLSv1_0 = $false
                        TLSv1_1 = $false
                        TLSv1_2 = $false
                        KeyExhange = $null
                        HashAlgorithm = $null
                        RemoteCertificate = $null
                    }

                    Test-TLSConnection -HostObject ([ref]$hostObject)
                    
                    if($null -eq $hostObject.KeyExhange)
                    {
                        Write-Host "Unable to negotiate a secure connection. Result details: $hostObject"
                        return $false
                    }
                    else
                    {
                        Write-Host "Connection negotiated successfully!" -ForegroundColor DarkGreen -BackgroundColor White               

                        $global:TLSv1_0 = $hostObject.TLSv1_0
                        $global:TLSv1_1 = $hostObject.TLSv1_1
                        $global:TLSv1_2 = $hostObject.TLSv1_2

                        if($hostObject.TLSv1_2 -eq $false)
                        {                    
                            Write-Host "TLS 1.2 is not supported. Please enable TLS 1.2." -ForegroundColor Yellow -BackgroundColor Red                   
                            
                            Write-Host "More details available here: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/agent-windows#configure-agent-to-use-tls-12"
                        }

                        #Write-Host "Connection details: $hostObject"
                    }                
                }
                catch
                {
                    Write-Host "Caught exception while testing connection to LA endpoints: $($_.Exception.Message)" -ForegroundColor Yellow -BackgroundColor Red
                    return 
                }
            }
        }
    }
    catch
    {
        Write-Host "Caught exception while testing connection to LA endpoints: $($_.Exception.Message)" -ForegroundColor Yellow -BackgroundColor Red
        return 
    }
    
    return 
}

function Test-TLSConnection
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ref]$HostObject
    )

    "ssl2", "ssl3", "tls", "tls11", "tls12" | ForEach-Object {
        $TcpClient = New-Object Net.Sockets.TcpClient
        $TcpClient.Connect($HostObject.Value.Host, $HostObject.Value.Port)
        $SslStream = New-Object Net.Security.SslStream $TcpClient.GetStream(),
            $true,
            ([System.Net.Security.RemoteCertificateValidationCallback]{ $true })
        $SslStream.ReadTimeout = 15000
        $SslStream.WriteTimeout = 15000
        try 
        {
            $SslStream.AuthenticateAsClient($HostObject.Value.Host,$null,$_,$false)
            $HostObject.Value.RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
            $HostObject.Value.KeyExhange = $SslStream.KeyExchangeAlgorithm
            $HostObject.Value.HashAlgorithm = $SslStream.HashAlgorithm
            $status = $true
        } 
        catch 
        {
            $status = $false
        }

        switch ($_) 
        {
            "ssl2" {$HostObject.Value.SSLv2 = $status}
            "ssl3" {$HostObject.Value.SSLv3 = $status}
            "tls" {$HostObject.Value.TLSv1_0 = $status}
            "tls11" {$HostObject.Value.TLSv1_1 = $status}
            "tls12" {$HostObject.Value.TLSv1_2 = $status}
        }
        # dispose objects to prevent memory leaks
        $TcpClient.Dispose()
        $SslStream.Dispose()
    }
}

#AMA Common

function determineAMAType 
{
    # if the registry path for Client AMA is not found, then AMA must be running on a server (either Azure or ARC)
    if (Test-Path -Path $global:onPremRegPath) {
      Write-Host "AMA is running on Windows Client machine"
      return "Client"
    } elseif (Test-Path -Path $global:vmDir) {
      Write-Host "AMA is running on Azure VM";
      return "AzVM"
    } elseif (Test-Path -Path $global:arcDir) {
      Write-Host "AMA is running on ARC server";
      return "ARC"
    } else {
      Write-Error "The script cannot determine the type of AMA running on the machine"
      return ""
    }
}

function parseEndpoint {
    param (
      $contentStr
    )
    $leftIndex = $contentStr.IndexOf('endpoint="') + 'endpoint="'.Length;
    $rightIndex = $contentStr.IndexOf('"', $leftIndex);
  
    return $contentStr.Substring($leftIndex, ($rightIndex-$leftIndex));
  }
#ARC agent
function CheckARCStatus 
{
    Write-Host "Checking Azure Connected Machine Agent Status..."
    $statusFile = "C:\ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json"
    if([System.IO.File]::Exists($statusFile))
    {
        Write-Host "Getting Connected Machine Agent configuration..."
    }
    else
    {
        Write-Host "Missing Azure Connected Machine Agent configuration file. Please run azcmagent check if you have installed the ARC agent." -ForegroundColor Yellow -BackgroundColor Red
        return
    }

    $azureInstanceInfo = GetARCInstanceInfo
    $tenantId = $azureInstanceInfo.tenantId
    $subscriptionId = $azureInstanceInfo.subscriptionId
    $resourceGroup = $azureInstanceInfo.resourceGroup
    $resourceName = $azureInstanceInfo.resourceName
    Write-Host "Machine is connected to tenant $tenantId in Subscription $subscriptionId and Resource Group $resourceGroup. Azure Connected Machine name is: $resourceName" -ForegroundColor DarkGreen -BackgroundColor White
    Write-Host "Checking ARC Agent services..."
    $himdsStatus = GetServiceStatus("himds")
    if ($himdsStatus -eq 'Running')
    {
        Write-Host "Agent Service(himds) is running" -ForegroundColor DarkGreen -BackgroundColor White
    }
    else 
    {
        Write-Host "Agent Service(himds) is not running. Machine may show as 'Disconnected' in the Azure Portal. Please run 'azcmagent logs' for further troubleshooting." -ForegroundColor Yellow -BackgroundColor Red
    }
    $gcStatus = GetServiceStatus("gcarcservice")
    if ($gcStatus -eq 'Running')
    {
        Write-Host "Guest Configuration(GC) service is running" -ForegroundColor DarkGreen -BackgroundColor White
    }
    else 
    {
        Write-Host "Guest Configuration(GC) service is not running. Machine may not be able to apply configuration changes. Please run 'azcmagent logs' for further troubleshooting." -ForegroundColor Yellow -BackgroundColor Red
    }
    $extensionStatus = GetServiceStatus("extensionservice")
    if ($extensionStatus -eq 'Running')
    {
        Write-Host "Extension service is running" -ForegroundColor DarkGreen -BackgroundColor White
    }
    else 
    {
        Write-Host "Extension service is not running. Machine may not be able to install new extensions. Please run 'azcmagent logs' for further troubleshooting." -ForegroundColor Yellow -BackgroundColor Red
    }
    $currentLocation = (Get-Location).Path
    Set-Location -Path "C:\Program Files\AzureConnectedMachineAgent"
    ./azcmagent show
    Set-Location -Path $currentLocation
}

function CheckARCEndpointsConnectivity 
{
    Write-Host "Checking if Azure Connected Machine Agent is present..."
    $statusFile = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
    if([System.IO.File]::Exists($statusFile))
    {
        Write-Host "Getting Endpoint connectivity..."
        $currentLocation = (Get-Location).Path
        Set-Location -Path "C:\Program Files\AzureConnectedMachineAgent"
        ./azcmagent check
        Set-Location -Path $currentLocation
    }
    else
    {
        Write-Host "Missing Azure Connected Machine Agent file. Please run azcmagent check if you have installed the ARC agent." -ForegroundColor Yellow -BackgroundColor Red
        return
    }
    
}
#AMA agent
function CheckAMAStatus
{
    # Collect basic information about all AMA processes
    $processNames = @(
      "'AMAExtHealthMonitor.exe'",
      "'MonAgentLauncher.exe'",
      "'MonAgentHost.exe'",
      "'MonAgentManager.exe'",
      "'MonAgentCore.exe'",
      "'AzurePerfCollectorExtension.exe'",
      "'MetricsExtension.Native.exe'",
      "'AMAService.exe'"
    )
    foreach ($process in $processNames) {
      $processs = Get-WmiObject Win32_Process -Filter "name = $process"
      if ($processs -eq $null) 
      {
        Write-Host "Process $process is not running. Please run the log collector script for additional information" -ForegroundColor Yellow -BackgroundColor Red
      }
      else 
      {
        $s1 = $processs.ProcessId
        Write-Host "Process $process with Id $s1 is running." -ForegroundColor DarkGreen -BackgroundColor White
      }
    }
}

function CheckAMAEndpointsConnectivity {
    # Collect network information
    if ($null -eq (Get-Command "curl.exe" -ErrorAction SilentlyContinue)) {
      Write-Error "curl.exe is not in path. Install curl.exe"
      return;
    }
    
    [string]$AMAType = determineAMAType
    if ($AMAType -eq "AzVM")
    {
        Write-Host "Connecting to IMDS at http://169.254.169.254/metadata/instance?api-version=2021-02-01" -ForegroundColor DarkGreen -BackgroundColor White
        $imdsEndpoint = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
        if ($PSVersionTable.PSVersion -lt "3.0.0") {
            $imdsRawResponse = curl.exe -v -H "Metadata: true" $imdsEndpoint;
            $imdsRawResponse | Out-File -FilePath $networkInfo -Append;
            # Manually parsing json response because convertfrom-json does not work on PS 2.0. Response does not seem to contain spaces, removing them just in case.
            $imdsRawResponse = $imdsRawResponse -replace '\s','';
            $subIdLength = 32;
            $subIdStartIndex = $imdsRawResponse.IndexOf("subscriptionId") + 'subscriptionId":"'.Length;
            $subId = $imdsRawResponse.Substring($subIdStartIndex, $subIdLength);
        } 
        else 
        {
            ($imdsResponse = curl.exe -v -H "Metadata: true" $imdsEndpoint | convertfrom-json)
            $subId = $imdsResponse.compute.subscriptionId
        }
  
        if ($subId) 
        {
            Write-Host "Connecting to Azure subscription endpoint 'https://management.azure.com/subscriptions/{0}?api-version=2014-04-01'" -ForegroundColor DarkGreen -BackgroundColor White
            $endpoint = ("https://management.azure.com/subscriptions/{0}?api-version=2014-04-01" -f $subId);
            curl.exe -v $endpoint
        } 
        else 
        {
            Write-Host "Connection to IMDS Failed and script checks show this is an Azure VM. Run the log collector script for more information." -ForegroundColor Yellow -BackgroundColor Red
        }
    }
    else 
    {
        Write-Host "Connecting to himds for ARC Machines at http://localhost:40342" -ForegroundColor DarkGreen -BackgroundColor White
        curl.exe -v "http://localhost:40342"
  
        Write-Host "Connecting to MCS endpoint 'https://global.handler.control.monitor.azure.com'" -ForegroundColor DarkGreen -BackgroundColor White
        curl.exe -v "https://global.handler.control.monitor.azure.com"
    }

    $parsedEndpoints = @{};
    $MAConfigLatestPath = "C:\WindowsAzure\Resources\AMADataStore.*\mcs\mcsconfig.latest.xml";
    $MAConfigLkgPath = "C:\WindowsAzure\Resources\AMADataStore.*\mcs\mcsconfig.lkg.xml";
  
    if (Test-Path -Path $MAConfigLatestPath) 
    {
        $Contents = Select-Xml -Path $MAConfigLatestPath -XPath "/MonitoringManagement/EventStreamingAnnotations/EventStreamingAnnotation/OMS/Content"
    } 
    elseif (Test-Path -Path $MAConfigLkgPath) 
    {
        $Contents = Select-Xml -Path $MAConfigLkgPath -XPath "/MonitoringManagement/EventStreamingAnnotations/EventStreamingAnnotation/OMS/Content"
    } 
    else 
    {
        Write-Host "Cannot find mcs config file under AMA datastore. Cannot parse endpoints information downloaded from AMCS." -ForegroundColor Yellow -BackgroundColor Red
    }
  
    if ($Contents) 
    {
        if ($Contents -is [Array]) 
        {
            $Contents | ForEach-Object {
                if(!$parsedEndpoints.ContainsKey((parseEndpoint $_.Node.Innerxml))) 
                {
                $parsedEndpoints.Add((parseEndpoint $_.Node.Innerxml), 0);
                }
            }
        } 
        else 
        {
            $parsedEndpoints.Add((parseEndpoint $Contents.Node.Innerxml), 0);
        }
            
        Write-Host "Connecting to endpoints found in mcsconfig file (ODS, GIG, etc...)"
        foreach ($endpoint in $parsedEndpoints.GetEnumerator())
        {
            $endpointUri = $endpoint.Name;
            Write-Host "Connecting to $endpointUri" -ForegroundColor DarkGreen -BackgroundColor White
            curl.exe -v $endpointUri
        }
    }
}

#MMA agent
function CheckMMAStatus
{
    Write-Log -Level INFO -NonDefaultLogFile $NonDefaultLogFile -FunctionName $MyInvocation.MyCommand -Message "Checking if all agent services are running"

    try
    {
        [bool]$allServicesRunning = $true
        $extensionService = Get-WmiObject Win32_Process -Filter "name = 'MMAExtensionHeartbeatService.exe'" | Select-Object Path | Out-String
        if($True -eq [string]::IsNullOrEmpty($extensionService))
        {
            Write-Host "MMA extension service is not running." -ForegroundColor Yellow -BackgroundColor Red
        }
        else
        {
            Write-Host "MMA extension service is running with path:" -ForegroundColor DarkGreen -BackgroundColor White
            Write-Host "$extensionService"
        }

        $healthService = Get-WmiObject Win32_Process -Filter "name = 'HealthService.exe'" | Select-Object Path | Out-String
        if($True -eq [string]::IsNullOrEmpty($healthService))
        {
            Write-Host "HealthService service is not running." -ForegroundColor Yellow -BackgroundColor Red
            $allServicesRunning = $false
        }
        else
        {
            Write-Host "HealthService is running with path:" -ForegroundColor DarkGreen -BackgroundColor White
            Write-Host "$healthService"
        }

        $monitoringHost = Get-WmiObject Win32_Process -Filter "name = 'MonitoringHost.exe'" | Select-Object Path | Out-String
        if($True -eq [string]::IsNullOrEmpty($monitoringHost))
        {
            Write-Host "MonitoringHost service is not running." -ForegroundColor Yellow -BackgroundColor Red
            $allServicesRunning = $false
        }
        else
        {
            Write-Host "MonitoringHost service is running with path" -ForegroundColor DarkGreen -BackgroundColor White
            Write-Host "$monitoringHost"
        }
        
        if($allServicesRunning -eq $true)
        {
            Write-Host "Services running check complete and all MMA Services are running" -ForegroundColor DarkGreen -BackgroundColor White
            return
        }
        else
        {
            Write-Host "Services running check complete. Some services are not running - check above output for details" -ForegroundColor Yellow -BackgroundColor Red
            return
        }
    }
    catch
    {
        Write-Host "Caught exception while checking for Agent services. Exception: $($_.Exception.Message)" -ForegroundColor Yellow -BackgroundColor Red
        return
    }
}

function CheckMMAEndpointsConnectivity
{
    Write-Host "Running connectivity tests. Please wait..." -ForegroundColor DarkGreen -BackgroundColor White

    [bool]$connectivityToolCheckPassed = RunCloudConnectionTool
    if($connectivityToolCheckPassed -eq $false)
    {
        Write-Error "TestCloudConnection tool has reported errors. Please check your network settings including firewall/gateway rules and ensure connectivity to Log Analytics" -ForegroundColor Yellow -BackgroundColor Red
        $global:success = $false
    }

    TestConnectivityToLAEndpoints
    
    if($global:TLSv1_2 -eq $true)
    {
        Write-Host "TLS 1.2 Is Enabled on the machine" -ForegroundColor DarkGreen -BackgroundColor White
    }

    elseif($global:TLSv1_2 -eq $false)
    {
        Write-Host "Connectivity checks to Log Analytics endpoints have failed. Please fix the errors reported above. TLS 1.2 is not enabled on this machine. Please enable. Steps for enabling it are available here: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/agent-windows#configure-agent-to-use-tls-12" -ForegroundColor Yellow -BackgroundColor Red
        $global:success = $false
        if($global:TLSv1_1 -eq $true)
        {
            Write-Host "TLS 1.1 is enabled on this machine. Please see TLS guidance here: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/log-analytics-agent#tls-12-protocol"
        }
        elseif($global:TLSv1_0 -eq $true)
        {
            Write-Host "TLS 1.0 is enabled on this machine. Please see TLS guidance here: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/log-analytics-agent#tls-12-protocol"
        }
    }
    
    $mmaCertCheckPassed = CheckIfMMACertPresent
    $mmaCertCheckPassed1 = $mmaCertCheckPassed[2]
    if($mmaCertCheckPassed1 -eq $false)
    {
        Write-Host "Microsoft Monitoring Agent certificate is not present on the machine." -ForegroundColor Yellow -BackgroundColor Red	
        $global:success = $false
        # force a fresh configuration
    }
    
    [bool]$imdsCheckPassed = GetIMDSMetadata[4]
    if($imdsCheckPassed -eq $false)
    {
        Write-Host "IMDS check failed. Please check if this Azure VM has connectivity. Ignore this error if the machine is not an Azure VM" -ForegroundColor Yellow -BackgroundColor Red
    }

    Write-Host "Connectivity tests run complete."

    if ($global:success -eq $false)
    {
        Write-Host "One or more tests failed. Please run the MMA Troubleshooter for additional context on the errors." -ForegroundColor Yellow -BackgroundColor Red
        return
    }
    else 
    {
        Write-Host "Connectivity tests run completed without major errors." -ForegroundColor DarkGreen -BackgroundColor White
        return
    }
}
#HW agent
function CheckHWStatus 
{
    return "success"
}

function CheckHWEndpointsConnectivity 
{
    return "success"
}

main
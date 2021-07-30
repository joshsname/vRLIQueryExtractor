Param(
    [String]$vRliFQDN,
    [PSCredential]$credentialFile,
    [String]$queryDate, # 27/07/21
    [String]$ipAddress,
    [String]$outFileName
)

Function Get-Token {
    Param(
        [String]$vRliFqdn,
        [PSCredential]$credentialFile
    )

    if (-not("dummy" -as [type])) {
        add-type -TypeDefinition @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    
    public static class Dummy {
        public static bool ReturnTrue(object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors) { return true; }
    
        public static RemoteCertificateValidationCallback GetDelegate() {
            return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
        }
    }
"@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()
    
    $username = $credentialFile.UserName
    $password = $credentialFile.GetNetworkCredential().Password

    $authURL = "https://" + $vRliFqdn + "/api/v1/sessions"
    $Type = "application/json"

    $AuthJSON =
    "{
        ""username"": ""$username"",
        ""password"": ""$password"",
        ""provider"": ""ActiveDirectory""
    }"

    Try { $sessionResponse = Invoke-RestMethod -Method POST -Uri $authURL -Body $AuthJSON -ContentType $Type -SkipCertificateCheck }
    Catch {
        $_.Exception.ToString()
        $error[0] | Format-List -Force
    }
    Return $sessionResponse
}

$authToken = Get-Token $vRliFQDN $credentialFile
$header = @{"Authorization"="Bearer "+$authToken.sessionId
"Accept"="application/json"}

$epochDate = [Math]::Floor([decimal](Get-Date([datetime]::parseexact($queryDate, 'dd/MM/yy', $null)).ToUniversalTime()-uformat "%s"))*1000
$5minutes = 300000
$startTime  = $epochDate
$endTime    = ($epochDate + $5minutes)

$queryFilter = "appname/dfwpktlogs/vmw_nsx_firewall_dst_port/!=53/text/CONTAINS%20$ipAddress"

$completeResults = @()
$baseURI = "https://" + $vRliFqdn + "/api/v1"

Write-Output "Starting log collection for the date of $queryDate."

for ($i=1; $i -le (60/5*24); $i++) {
    $testQuery = "$baseURI/events/timestamp/>=$startTime/timestamp/<=$endTime/$queryFilter/?view=SIMPLE&limit=20000"
    $Results = Invoke-RestMethod -Uri $testQuery -method Get -Headers $header -SkipCertificateCheck
    if ($Results.numResults -gt 0) {
        $Results.results | foreach-object {
            $completeResults += New-Object PSObject -Property @{ 'log' = $_.text }
        }
    }
    Write-Output "Finshed collection $i of $(60/5*24). Found $($Results.numResults) events."
    $startTime  = $epochDate + ($5minutes * $i)
    $endTime    = ($epochDate  + ($5minutes * $i) + $5minutes)
}

Write-Output "Finished collection. Processing results and removing duplicates."

for ($i=0; $i -lt $completeResults.Length; $i++) {
    $completeResults[$i] = $completeResults[$i].log -Replace '.*Z ', ''
}

$numOfPreEvents = ($completeResults | measure-object | Select-Object Count).Count
$numOfUniqueEvents = ($completeResults | sort-object log | get-unique | measure-object | select-Object Count).Count
$completeResults = $completeResults | sort-object log | get-unique

Write-Output "Removed $($numOfPreEvents-$numOfUniqueEvents) duplicate events."

$completeResults | Out-File -path "test.csv"
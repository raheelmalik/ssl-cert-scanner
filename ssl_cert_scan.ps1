
##Cert function borrowed from: http://en-us.sysadmins.lv/Lists/Posts/Post.aspx?ID=60

$dict_file = "server_dictionary.csv"  ##replace $dict_file with full path of csv
#Populate array from csv
$servers = Import-Csv $dict_file

function Test-WebServerSSL {
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$URL,
        [Parameter(Position = 1)]
        [ValidateRange(1,65535)]
        [int]$Port = 443,
        [Parameter(Position = 2)]
        [Net.WebProxy]$Proxy,
        [Parameter(Position = 3)]
        [int]$Timeout = 15000,
        [switch]$UseUserContext
    )
Add-Type @"
    using System;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    namespace PKI {
        namespace Web {
            public class WebSSL {
            public Uri OriginalURi;
            public Uri ReturnedURi;
            public X509Certificate2 Certificate;
            //public X500DistinguishedName Issuer;
            //public X500DistinguishedName Subject;
            public string Issuer;
            public string Subject;
            public string[] SubjectAlternativeNames;
            public bool CertificateIsValid;
            //public X509ChainStatus[] ErrorInformation;
            public string[] ErrorInformation;
            public HttpWebResponse Response;
            }
        }
    }
"@
    $ConnectString = "https://$url`:$port"
    $WebRequest = [Net.WebRequest]::Create($ConnectString)
    $WebRequest.Proxy = $Proxy
    $WebRequest.Credentials = $null
    $WebRequest.Timeout = $Timeout
    $WebRequest.AllowAutoRedirect = $true
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    try {$Response = $WebRequest.GetResponse()}
    catch {}
    if ($WebRequest.ServicePoint.Certificate -ne $null) {
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
        try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
        catch {$SAN = $null}
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)
        [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
        $Status = $chain.Build($Cert)
        New-Object PKI.Web.WebSSL -Property @{
            OriginalUri = $ConnectString;
            ReturnedUri = $Response.ResponseUri;
            Certificate = $WebRequest.ServicePoint.Certificate;
            Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
            Subject = $WebRequest.ServicePoint.Certificate.Subject;
            SubjectAlternativeNames = $SAN;
            CertificateIsValid = $Status;
            Response = $Response;
            ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
        }
        $chain.Reset()
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    } else {
        Write-Error $Error[0]
    }
} ########## Function End

#Initialize table for output reporting
$table = New-Object system.Data.DataTable
$col0 = New-Object system.Data.DataColumn "Name",([string])
$col00 = New-Object system.Data.DataColumn "ServerName",([string])
$col1 = New-Object system.Data.DataColumn "URI",([string])
$col2 = New-Object system.Data.DataColumn "Valid",([string])
$col3 = New-Object system.Data.DataColumn "Issued",([datetime])
$col4 = New-Object system.Data.DataColumn "Expires",([datetime])
$col5 = New-Object system.Data.DataColumn "SerialNumber",([string])
$col55 = New-Object system.Data.DataColumn "ErrInfo",([string])
$col6 = New-Object system.Data.DataColumn "Issuer",([string])
$table.columns.add($col0)
$table.columns.add($col00)
$table.columns.add($col1)
$table.columns.add($col2)
$table.columns.add($col3)
$table.columns.add($col4)
$table.columns.add($col5)
$table.columns.add($col55)
$table.columns.add($col6)

foreach ($item in $servers | ? {$_.name -notlike "#*"}){
    $temp_cert = $null
    write "$($item.name) -> $($item.server):$($item.Port)"
    $temp_cert = Test-WebServerSSL $item.server -Port $item.port   #Test each item from array
    $table.Rows.add(
        $item.name,
        $item.server,
        $temp_cert.OriginalURi,
        $temp_cert.CertificateIsValid,
        (get-date $temp_cert.Certificate.NotBefore -Format MM-dd-yyyy),
        (get-date $temp_cert.Certificate.NotAfter -Format MM-dd-yyyy),
        $temp_cert.Certificate.SerialNumber,
        [string]$temp_cert.ErrorInformation,
        $temp_cert.Issuer
    ) | Out-Null    #Write to table
}

##Display table
$table | sort Issued | Out-GridView -Title "All certs"
$table | ? {($_.valid -eq $false) -or ($_.expires -lt (get-date).AddDays(30))} | sort Issued | Out-GridView -Title "Certs not valid or expiring within 30 days"

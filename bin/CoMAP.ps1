param (
    [ValidateScript({
        if ($_ -match "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$") {
            $true
        } else {
            throw "Invalid IP address: $_"
        }
    })]
    [string[]]$IpRange,

    [string]$portCategory = 'SSH',
    [string]$OutputFile,
    [ValidateSet('PlainText', 'Json', 'Xml')]
    [string]$OutputFormat = 'PlainText',
    [ValidateSet('Silent', 'Norm')]
    [string]$Mode = 'Norm',
    [int]$SilentModeWaitTime = 5
)

$ErrorLog = 'ErrorLog.txt'

# Your existing ports definition
$ports = switch ($portCategory) {
    'Games' { '3074', '3478..3480', '27015..27030', '3724', '5000..5500', '25565' }
    'DB' { '1433', '3306', '5432', '1521', '27017', '6379', '9042', '8086' } # Add your DB ports here
    'AD' { '389', '636', '3268', '3269' } # Add your AD and LDAP ports here
    'Web' { '80', '443' } # Add your Web ports here
    'Network' { '20', '21', '22', '23', '25', '53', '67', '68', '69' } # Add your Network ports here
    'Proxies' { '3128', '8080', '8118' } # Add your Proxy ports here
    'VNC' { '5800..5899', '5900..5999' } # Add your VNC ports here
    'SIEM' { '514', '1514', '5601', '8000', '8089', '9997', '51413', '7734', '7736', '7737', '8081', '9200' } # Add your SIEM ports here
    'Auth' { '1812', '1813', '88', '749' } # Add your Authentication ports here
    'Apps' { '10000', '1194', "2375", "2376" } # Add your App ports here
}

# New service and category mappings
$portServiceMap = @{
    '3074' = 'Xbox Live';
    '3478..3480' = 'PlayStation Network';
    '27015..27030' = 'Steam';
    '3724' = 'World of Warcraft';
    '5000..5500' = 'League of Legends';
    '25565' = 'Minecraft';
    '1433' = 'MSSQL'; # Add your DB services here
    '3306' = 'MySQL';
    '8086' = 'InfluxDB';
    '5432' = 'PostgreSQL';
    '1521' = 'Oracle';
    '27017' = 'MongoDB';
    '6379' = 'Redis';
    '9042' = 'Cassandra';
    '389' = 'LDAP'; # Add your AD and LDAP services here
    '636' = 'LDAPS';
    '3268' = 'AD Global Catalog';
    '3269' = 'AD Global Catalog over SSL';
    '80' = 'HTTP'; # Add your Web services here
    '443' = 'HTTPS';
    '20' = 'FTP Data'; # Add your Network services here
    '21' = 'FTP Control';
    '22' = 'SSH';
    '23' = 'Telnet';
    '25' = 'SMTP';
    '53' = 'DNS';
    '67' = 'DHCP Server';
    '68' = 'DHCP Client';
    '69' = 'TFTP';
    '3128' = 'Squid Proxy'; # Add your Proxy services here
    '8080' = 'HTTP Proxy';
    '8118' = 'Privoxy';
    '5800..5899' = 'VNC'; # Add your VNC services here
    '5900..5999' = 'VNC';
    '514' = 'Syslog'; # Add your SIEM services here
    '1514' = 'Syslog over TLS';
    '5601' = 'Kibana';
    '8000' = 'Splunk';
    '8089' = 'Splunk Management';
    '9997' = 'Splunk Indexing';
    '51413' = 'QRadar Event Collection';
    '7734' = 'QRadar Flow Collection';
    '7736' = 'QRadar Console';
    '7737' = 'QRadar Admin';
    '8081' = 'AlienVault';
    '9200' = 'Elasticsearch';
    '1812' = 'RADIUS'; # Add your Authentication services here
    '1813' = 'RADIUS Accounting';
    '88' = 'Kerberos';
    '749' = 'Kerberos Admin';
    '10000' = 'Webmin'; # Add your App services here
    '1194' = 'OpenVPN';
    '2375' = 'Docker';
    '2376' = 'Docker';
}

$serviceCategoryMap = @{
    'Xbox Live' = 'Games';
    'PlayStation Network' = 'Games';
    'Steam' = 'Games';
    'World of Warcraft' = 'Games';
    'League of Legends' = 'Games';
    'Minecraft' = 'Games';
    'MSSQL' = 'DB'; # Add your DB category here
    'MySQL' = 'DB';
    'InfluxDB' = 'DB';
    'PostgreSQL' = 'DB';
    'Oracle' = 'DB';
    'MongoDB' = 'DB';
    'Redis' = 'DB';
    'Cassandra' = 'DB';
    'LDAP' = 'AD'; # Add your AD category here
    'LDAPS' = 'AD';
    'AD Global Catalog' = 'AD';
    'AD Global Catalog over SSL' = 'AD';
    'HTTP' = 'Web'; # Add your Web category here
    'HTTPS' = 'Web';
    'FTP Data' = 'Network'; # Add your Network category here
    'FTP Control' = 'Network';
    'SSH' = 'Network';
    'Telnet' = 'Network';
    'SMTP' = 'Network';
    'DNS' = 'Network';
    'DHCP Server' = 'Network';
    'DHCP Client' = 'Network';
    'TFTP' = 'Network';
    'Squid Proxy' = 'Proxies'; # Add your Proxy category here
    'HTTP Proxy' = 'Proxies';
    'Privoxy' = 'Proxies';
    'VNC' = 'VNC'; # Add your VNC category here
    'Syslog' = 'SIEM'; # Add your SIEM category here
    'Syslog over TLS' = 'SIEM';
    'Kibana' = 'SIEM';
    'Splunk' = 'SIEM';
    'Splunk Management' = 'SIEM';
    'Splunk Indexing' = 'SIEM';
    'QRadar Event Collection' = 'SIEM';
    'QRadar Flow Collection' = 'SIEM';
    'QRadar Console' = 'SIEM';
    'QRadar Admin' = 'SIEM';
    'AlienVault' = 'SIEM';
    'Elasticsearch' = 'SIEM';
    'RADIUS' = 'Authentication'; # Add your Authentication category here
    'RADIUS Accounting' = 'Auth';
    'Kerberos' = 'Auth';
    'Kerberos Admin' = 'Auth';
    'Webmin' = 'Apps'; # Add your App category here
    'OpenVPN' = 'Apps';
    'Docker' = 'Apps';
}

$ErrorLog = Join-Path -Path $HOME -ChildPath "CoMap\Logs\errorLog.txt"
if (!(Test-Path -Path $ErrorLog)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $ErrorLog)
}

# Define the output directory
$OutputDirectory = Join-Path -Path $HOME -ChildPath 'CoMAP\Targets'

# Define the output file path
$OutputFile = Join-Path -Path $OutputDirectory -ChildPath ("$OutputFile" + "_" + $Date + ".log")

# Create the directory if it doesn't exist
if (!(Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

# Get the current date in short format
$Date = Get-Date -Format 'yyyyMMdd'

foreach ($ip in $IpRange) {
    $ipResults = @()
    foreach ($port in $ports) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $service = $portServiceMap["$port"]
        $category = $serviceCategoryMap["$service"]
        try {
            $tcpClient.Connect($ip, $port)
            $result = @{
                "IP" = $ip
                "Port" = $port
                "Service" = $service
                "Category" = $category
                "Status" = "Open"
                "CheckTime" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            Write-Output "Checked $ip port $port ($service) at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"): Open" > $null
        } catch {
            $result = @{
                "IP" = $ip
                "Port" = $port
                "Service" = $service
                "Category" = $category
                "Status" = "Closed"
                "CheckTime" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $errorMessage = "Error checking $ip port $port ($service) at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"): Connection refused"
            $errorMessage | Out-File -Append -FilePath $OutputFile
            $_.Exception.Message | Out-File -Append -FilePath $ErrorLog
            Write-Error $errorMessage > $null
        } finally {
            $tcpClient.Close()
        }
        $ipResults += $result
    }
    $allResults += $ipResults
}

# If an output file was specified, write the results to the file
if ($OutputFile) {
    switch ($OutputFormat) {
        'PlainText' {
            $allResults | Out-File -FilePath $OutputFile
        }
        'Json' {
            $allResults | ConvertTo-Json | Out-File -FilePath $OutputFile
        }
        'Xml' {
            $allResults | ConvertTo-Xml | Out-File -FilePath $OutputFile
        }
    }
}
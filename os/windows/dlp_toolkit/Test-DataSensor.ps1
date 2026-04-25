# ==============================================================================
# DATA SENSOR QA TRIGGER SCRIPT
# Run this in a separate PowerShell window to validate detection vectors
# ==============================================================================

Write-Host "[*] Initiating Data Sensor DLP Validation..." -ForegroundColor Cyan

# 1. Test Data In Use (Clipboard Monitoring)
Write-Host "    -> Testing Clipboard Hook (Regex Match)..." -ForegroundColor Gray
Set-Clipboard -Value "Here is the emergency AWS Key: AKIATESTING123456789 do not share."
Start-Sleep -Seconds 2

# 2. Test Data At Rest (Plaintext File Inspection & Literal Match)
Write-Host "    -> Testing Deep File Inspection (Project Name Match)..." -ForegroundColor Gray
$TestDir = "C:\temp_dlp_qa"
if (-not (Test-Path $TestDir)) { New-Item -ItemType Directory -Path $TestDir | Out-Null }
$TextFile = "$TestDir\Draft_Notes.txt"
Set-Content -Path $TextFile -Value "We need to discuss the budget for Project Titan before Q3."
Start-Sleep -Seconds 2

# 3. Test Data At Rest (Archive Expansion & Classification Match)
Write-Host "    -> Testing ZIP Archive Expansion (Classification Match)..." -ForegroundColor Gray
$XmlFile = "$TestDir\payload.xml"
Set-Content -Path $XmlFile -Value "<data><tag>CONFIDENTIAL</tag><value>1000</value></data>"
Compress-Archive -Path $XmlFile -DestinationPath "$TestDir\packaged_data.zip" -Force
Start-Sleep -Seconds 2

# 4. Test Data In Motion (Network Threat Intel)
Write-Host "    -> Testing Outbound Network Sockets (Threat Intel Match)..." -ForegroundColor Gray
try {
    # Forces a DNS resolution and TCP SYN to a known exfiltration webhook domain from your Intel feed
    Invoke-WebRequest -Uri "https://pastebin.com/raw/test" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
} catch {}

Write-Host "[+] Validation Triggers Executed. Check your Data Sensor Dashboard." -ForegroundColor Green
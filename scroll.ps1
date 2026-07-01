Write-Host "Process script... (Press Ctrl + C to stop)"
$shell = New-Object -ComObject WScript.Shell

while ($true) {
    # Get current hour and minute
    $now = Get-Date
    $hour = $now.Hour
    $minute = $now.Minute

    # 1. First half of lunch break (11:30 ~ 12:30) -> Sleep for 30 minutes
    if (($hour -eq 11 -and $minute -ge 30) -or ($hour -eq 12 -and $minute -le 30)) {
        Write-Host "Current time is $($now.ToString('HH:mm')) - Early lunch break, waiting for 30 minutes..."
        Start-Sleep -Seconds 1800 # 30 minutes
        continue
    }

    # 2. Second half of lunch break (12:31 ~ 12:59) -> Sleep for 5 minutes
    if ($hour -eq 12 -and $minute -gt 30) {
        Write-Host "Current time is $($now.ToString('HH:mm')) - Late lunch break, waiting for 5 minutes..."
        Start-Sleep -Seconds 300 # 5 minutes
        continue
    }

    # Active time (Outside 11:30 ~ 13:00) -> Press Scroll Lock twice
    $shell.SendKeys('{SCROLLLOCK}')
    Start-Sleep -Seconds 1
    $shell.SendKeys('{SCROLLLOCK}')
    
    # Wait for 3 minutes (180 seconds)
    Start-Sleep -Seconds 180
}
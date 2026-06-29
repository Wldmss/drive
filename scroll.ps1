Write-Host "스크립트 실행.. (종료하려면 Ctrl + C)"
$shell = New-Object -ComObject WScript.Shell

while ($true) {
    # ScrollLock 키를 두 번 눌러서 원래 상태 유지하며 신호만 전달
    $shell.SendKeys('{SCROLLLOCK}')
    Start-Sleep -Seconds 1
    $shell.SendKeys('{SCROLLLOCK}')
    
    # 3분(180초) 대기
    Start-Sleep -Seconds 180
}
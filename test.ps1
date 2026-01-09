########################################################################################################
#                                                                                                      #
# File Name: Malware-Byte-Premium-Reset.ps1     # Output: Schedule a task that resets the              #
# Author: K Souhaib (Fixed Edition)             # Malwarebytes Premium trial by changing the           #
# Version: 2.1 - Fix Applied                    # MachineGuid registry value                           #
#                                                                                                      #
########################################################################################################

# Script configuration
$Global:ScriptConfig = @{
    TaskName        = "SystemMaintenanceTask"
    TaskPath        = "\"
    TaskDescription = "System maintenance and registry optimization task"
    ResetInterval   = 13
    RegistryPath    = "HKLM:\SOFTWARE\Microsoft\Cryptography"
    RegistryKey     = "MachineGuid"
    LogFile         = "$env:TEMP\SystemMaintenance.log"
    MBAMPaths       = @(
        "${env:ProgramFiles(x86)}\Malwarebytes\Anti-Malware\malwarebytes_assistant.exe",
        "${env:ProgramFiles}\Malwarebytes\Anti-Malware\malwarebytes_assistant.exe"
    )
}

function Center-Text($text){
    $width = [console]::WindowWidth
    $PadLeft = [math]::max(0,($width - $text.Length) /2 )
    return (' ' * $PadLeft) + $text
}

function Write-Centered($text, $color="White") {
    Write-Host (Center-Text $text) -ForegroundColor $color
}

function Custom-Window{
    [System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::Clear()
    [Console]::Title = "Reset Malwarebytes Trial Tool"
    [Console]::BackgroundColor = "Black"
    [Console]::ForegroundColor = "Cyan"
    [Console]::Clear()
    [Console]::SetWindowSize(73, 22)
    [Console]::BufferWidth = [Console]::WindowWidth
    [Console]::BufferHeight = [Console]::WindowHeight
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Message,
        
        [Parameter(Mandatory = $false)]
        # FIXED: Added "Success" to the ValidateSet to prevent the crash
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string] $Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Success" { Write-Host $logEntry -ForegroundColor Cyan }
        "Info"    { Write-Host $logEntry -ForegroundColor Green }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
    }
    
    try {
        Add-Content -Path $Global:ScriptConfig.LogFile -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Host "Unable to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-MalwarebytesPath {
    foreach ($path in $Global:ScriptConfig.MBAMPaths) {
        if (Test-Path $path) { return $path }
    }
    return $null
}

function Stop-MalwarebytesProcesses {
    Write-Log -Message "Stopping Malwarebytes processes..." -Level "Info"
    $mbamPath = Find-MalwarebytesPath
    if ($mbamPath) {
        try {
            Start-Process -FilePath $mbamPath -ArgumentList "--stopservice" -Wait -WindowStyle Hidden
            Start-Sleep -Seconds 2
        } catch {}
    }
    $processes = @("MBAMService", "mbam", "malwarebytes", "mbamtray")
    foreach ($proc in $processes) {
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Message "Malwarebytes processes stopped" -Level "Info"
}

function Start-MalwarebytesProcesses {
    Write-Log -Message "Starting Malwarebytes processes..." -Level "Info"
    $mbamPath = Find-MalwarebytesPath
    if ($mbamPath) {
        Start-Process -FilePath $mbamPath -WindowStyle Hidden
        Write-Log -Message "Malwarebytes restarted successfully" -Level "Info"
    }
}

function Create-ScheduledTaskHybrid {
    try {
        $existingTask = Get-ScheduledTask -TaskName $Global:ScriptConfig.TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $Global:ScriptConfig.TaskName -Confirm:$false
        }
        $taskScriptPath = "$env:TEMP\SystemMaintenanceTask.ps1"
        $taskScriptContent = @"
try {
    `$newGuid = [System.Guid]::NewGuid().ToString()
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -Value `$newGuid
    exit 0
} catch { exit 1 }
"@
        $taskScriptContent | Out-File -FilePath $taskScriptPath -Force -Encoding UTF8
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$taskScriptPath`""
        $taskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval $Global:ScriptConfig.ResetInterval -At (Get-Date).ToString("HH:mm")
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $task = New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger
        Register-ScheduledTask -TaskName $Global:ScriptConfig.TaskName -InputObject $task
        return $true
    } catch { return $false }
}

function Show-Menu {
    Clear-Host
    Write-Host "`n               Github: @0xSCfL" -ForegroundColor White
    Write-Centered " _____________________________________________"
    Write-Centered " Malwarebytes Reset Trial Tool - Fixed"
    Write-Centered " _____________________________________________"
    Write-Host ""
    Write-Host "               [1] Complete Reset (Stop → Reset → Start)" -ForegroundColor Green
    Write-Host "               [2] Quick Registry Reset Only" -ForegroundColor Yellow
    Write-Host "               [3] Setup Automatic Reset Schedule" -ForegroundColor Yellow
    Write-Host "               [Q] Quit" -ForegroundColor Red
    $choice = Read-Host "`n > Enter your choice"
    return $choice
}

# Main Logic
if (-not (Test-AdminPrivileges)) {
    Write-Host "[X] Administrator privileges required." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    Exit 1
}

$exit = $false
while (-not $exit) {
    Custom-Window
    $choice = Show-Menu
    switch ($choice) {
        '1' {
            Stop-MalwarebytesProcesses
            Write-Log "Querying scheduled task..." "Info"
            if (Create-ScheduledTaskHybrid) { Write-Log "Scheduled task created." "Success" }
            $newGuid = [System.Guid]::NewGuid().ToString()
            Set-ItemProperty -Path $Global:ScriptConfig.RegistryPath -Name $Global:ScriptConfig.RegistryKey -Value $newGuid
            Write-Log "MachineGuid changed to: $newGuid" "Success"
            Start-MalwarebytesProcesses
            Read-Host "Reset complete. Press Enter..."
        }
        '2' {
            $newGuid = [System.Guid]::NewGuid().ToString()
            Set-ItemProperty -Path $Global:ScriptConfig.RegistryPath -Name $Global:ScriptConfig.RegistryKey -Value $newGuid
            Write-Host "Registry reset to $newGuid" -ForegroundColor Green
            Read-Host "Press Enter..."
        }
        '3' {
            if (Create-ScheduledTaskHybrid) { Write-Host "Schedule created!" -ForegroundColor Green }
            Read-Host "Press Enter..."
        }
        'Q' { $exit = $true }
        'q' { $exit = $true }
    }
}

# SKU-sensitive checks for a probe host (run once, before pre-flight's idle
# baseline; this script makes WMI calls). Writes one JSON file.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\probe\win_sku_checks.ps1 -Out C:\probe\sku\sku.json
#
# 1. Drivers: service control manager list vs Win32_SystemDriver, for SELECT Name
#    and for the catalog's drv property set and each configuration property;
#    missing names get their registry ImagePath and whether the binary exists.
# 2. The three catalog queries that fail on Server 2019, run verbatim, plus the
#    class definitions they depend on.
# 3. __CacheControl per class and __ProviderHostQuotaConfiguration.
param([Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Stop'
$r = [ordered]@{ utc_start = [DateTime]::UtcNow.ToString('o'); host = $env:COMPUTERNAME }

function Try-Run([scriptblock]$b) {
    try { $v = & $b; @{ ok = $true; value = $v } }
    catch { @{ ok = $false; error = $_.Exception.Message; hresult = ('0x{0:X8}' -f $_.Exception.HResult) } }
}

# 1. Drivers (SCM side is ServiceController.GetDevices: no WMI)
Add-Type -AssemblyName System.ServiceProcess
$scm = [System.ServiceProcess.ServiceController]::GetDevices() | ForEach-Object { $_.ServiceName }
$scmSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$scm, [StringComparer]::OrdinalIgnoreCase)
$selects = [ordered]@{
    'Name'         = 'SELECT Name FROM Win32_SystemDriver'
    'Name, State'  = 'SELECT Name, State FROM Win32_SystemDriver'
    'catalog drv'  = 'SELECT Name, DisplayName, PathName, StartMode, StartName, State, ServiceType, Description FROM Win32_SystemDriver'
    '*'            = 'SELECT * FROM Win32_SystemDriver'
}
foreach ($p in 'DisplayName', 'PathName', 'StartMode', 'StartName', 'ServiceType', 'Description') { $selects["Name, $p"] = "SELECT Name, $p FROM Win32_SystemDriver" }
$drv = [ordered]@{ scm_count = $scm.Count; queries = [ordered]@{} }
$missingAll = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($k in $selects.Keys) {
    $res = Try-Run { @(Get-CimInstance -Query $selects[$k] | ForEach-Object { $_.Name }) }
    if ($res.ok) {
        $names = $res.value
        $set = [System.Collections.Generic.HashSet[string]]::new([string[]]$names, [StringComparer]::OrdinalIgnoreCase)
        $missing = @($scm | Where-Object { -not $set.Contains($_) })
        $extra = @($names | Where-Object { -not $scmSet.Contains($_) })
        $missing | ForEach-Object { [void]$missingAll.Add($_) }
        $drv.queries[$k] = [ordered]@{ wql = $selects[$k]; rows = $names.Count; missing_vs_scm = $missing; extra_vs_scm = $extra }
    } else { $drv.queries[$k] = [ordered]@{ wql = $selects[$k]; error = $res.error; hresult = $res.hresult } }
}
$drv.missing_detail = @(foreach ($n in $missingAll) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
    $img = (Get-ItemProperty -Path $key -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    $path = $null
    if ($img) {
        $path = $img -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '^System32\\', "$env:SystemRoot\System32\" -replace '^\\\?\?\\', ''
    }
    [ordered]@{ name = $n; image_path = $img; resolved = $path; binary_exists = if ($path) { Test-Path -LiteralPath $path } else { $null };
                start = (Get-ItemProperty -Path $key -Name Start -ErrorAction SilentlyContinue).Start;
                type = (Get-ItemProperty -Path $key -Name Type -ErrorAction SilentlyContinue).Type }
})
$r.drivers = $drv

# 2. The Server 2019 silent-failure queries, verbatim, and the classes behind them
function Class-Info($ns, $cls) {
    $c = Try-Run { Get-CimClass -Namespace $ns -ClassName $cls }
    if ($c.ok) { [ordered]@{ exists = $true; superclass = $c.value.CimSuperClassName; properties = @($c.value.CimClassProperties | ForEach-Object { $_.Name }) } }
    else { [ordered]@{ exists = $false; error = $c.error; hresult = $c.hresult } }
}
$q = [ordered]@{}
foreach ($t in @(
        @('sub_consumer', 'root/subscription', 'SELECT Name FROM __EventConsumer'),
        @('fw_app', 'root/StandardCimv2', 'SELECT InstanceID, Program, Package FROM MSFT_NetApplicationFilter'),
        @('task_info', 'root/Microsoft/Windows/TaskScheduler', 'SELECT TaskName, TaskPath, LastRunTime, NextRunTime, LastTaskResult FROM MSFT_ScheduledTaskInfo'))) {
    $res = Try-Run { @(Get-CimInstance -Namespace $t[1] -Query $t[2]).Count }
    $q[$t[0]] = [ordered]@{ namespace = $t[1]; wql = $t[2]; ok = $res.ok; rows = $res.value; error = $res.error; hresult = $res.hresult }
}
$r.catalog_queries = $q
$derived = Try-Run { @(Get-CimClass -Namespace root/subscription | Where-Object { $_.CimSuperClassName -eq '__EventConsumer' } |
        ForEach-Object { [ordered]@{ class = $_.CimClassName; has_name = [bool]($_.CimClassProperties | Where-Object Name -eq 'Name') } }) }
$r.classes = [ordered]@{
    '__EventConsumer'           = Class-Info 'root/subscription' '__EventConsumer'
    '__EventConsumer derived'   = $derived
    'MSFT_NetApplicationFilter' = Class-Info 'root/StandardCimv2' 'MSFT_NetApplicationFilter'
    'MSFT_ScheduledTaskInfo'    = Class-Info 'root/Microsoft/Windows/TaskScheduler' 'MSFT_ScheduledTaskInfo'
    'MSFT_TaskDynamicInfo'      = Class-Info 'root/Microsoft/Windows/TaskScheduler' 'MSFT_TaskDynamicInfo'
}

# 3. Provider unload interval and host quotas
$r.cache_control = Try-Run { @(Get-CimInstance -Namespace root -ClassName __CacheControl | ForEach-Object { [ordered]@{ class = $_.CimClass.CimClassName; name = $_.Name; clear_after = $_.ClearAfter } }) }
$r.provider_host_quota = Try-Run { @(Get-CimInstance -Namespace root -ClassName __ProviderHostQuotaConfiguration | ForEach-Object {
            [ordered]@{ MemoryPerHost = $_.MemoryPerHost; MemoryAllHosts = $_.MemoryAllHosts; ThreadsPerHost = $_.ThreadsPerHost; HandlesPerHost = $_.HandlesPerHost; ProcessLimitAllHosts = $_.ProcessLimitAllHosts } }) }

$r.utc_end = [DateTime]::UtcNow.ToString('o')
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$r | ConvertTo-Json -Depth 8 | Set-Content -Path $Out -Encoding UTF8
"wrote $Out"

# KokonaChat 本机双实例联调脚本
# 用法（管理员 PowerShell）：
#   powershell -ExecutionPolicy Bypass -File scripts\debug-test.ps1
#
# 功能：
#   1) 放行 kokonachat.exe 的 UDP 入站（Windows 防火墙默认 BlockInbound，需放行才能回环联调）
#   2) 生成两个临时实例 a / b，互加好友
#   3) 以 --debug 终端聊天模式启动两个实例，A 自动发送一条消息验证 B 能否收到
# 结果写入 %TEMP%\kokona-debug\result.txt（供自动化读取）。
#
# 手动玩法：脚本内也可加 -Manual，然后两个终端分别
#   kokonachat --data-dir %TEMP%\kokona-debug\a start --port 12221 --debug
#   kokonachat --data-dir %TEMP%\kokona-debug\b start --port 12222 --debug

param(
    [int]$PortA = 12221,
    [int]$PortB = 12222,
    [switch]$Manual
)

$ErrorActionPreference = 'Stop'
$tmp = Join-Path $env:TEMP 'kokona-debug'
$resultFile = Join-Path $tmp 'result.txt'

function Write-Result([string]$msg) {
    try { Set-Content -LiteralPath $resultFile -Value $msg -Encoding ascii } catch { }
    Write-Host $msg
}

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'target\debug\kokonachat.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path $root 'target\release\kokonachat.exe' }
if (-not (Test-Path $exe)) {
    Write-Result '[FAIL] 未找到 kokonachat.exe，请先 cargo build（或 cargo build --release）'
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[WARN] 当前不是管理员：无法放行防火墙，本机回环可能收不到 UDP。'
}

# ---- 1) 防火墙放行（需管理员）----
netsh advfirewall firewall delete rule name="kokonachat-debug" 2>&1 | Out-Null
netsh advfirewall firewall add rule name="kokonachat-debug" dir=in action=allow program="$exe" protocol=UDP 2>&1 | Out-Null

# ---- 2) 准备临时实例 ----
$da = Join-Path $tmp 'a'
$db = Join-Path $tmp 'b'
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $da, $db | Out-Null

function Get-Id([string]$dir) {
    (& $exe --data-dir $dir init 2>$null | Select-String '[0-9a-f]{64}' | Select-Object -First 1).Matches[0].Value
}
$idA = Get-Id $da
$idB = Get-Id $db
& $exe --data-dir $da friend add b $idB "127.0.0.1:$PortB" 2>&1 | Out-Null
& $exe --data-dir $db friend add a $idA "127.0.0.1:$PortA" 2>&1 | Out-Null

# ---- 3) 启动两个 --debug 实例 ----
$oa = Join-Path $tmp 'a.out';  $ob = Join-Path $tmp 'b.out'
$ea = Join-Path $tmp 'a.err';  $eb = Join-Path $tmp 'b.err'

if ($Manual) {
    $pb = Start-Process $exe -ArgumentList "start", "--port", "$PortB", "--data-dir", "$db", "--debug" `
        -WindowStyle Hidden -RedirectStandardOutput $ob -RedirectStandardError $eb -PassThru
    Start-Sleep -Seconds 2
    $pa = Start-Process $exe -ArgumentList "start", "--port", "$PortA", "--data-dir", "$da", "--debug" `
        -WindowStyle Hidden -RedirectStandardOutput $oa -RedirectStandardError $ea -PassThru
    Write-Result "OK 手动模式：A=$PortA B=$PortB 已启动。data-dir: $da / $db"
    Read-Host '按回车停止实例'
    Stop-Process -Id $pa.Id, $pb.Id -Force -ErrorAction SilentlyContinue
    exit 0
}

# 自动验证模式
$pb = Start-Process $exe -ArgumentList "start", "--port", "$PortB", "--data-dir", "$db", "--debug" `
    -WindowStyle Hidden -RedirectStandardOutput $ob -RedirectStandardError $eb -PassThru
Start-Sleep -Seconds 2
"hello from A`n/quit" | Out-File -Encoding ascii (Join-Path $tmp 'stdin_a.txt')
$pa = Start-Process $exe -ArgumentList "start", "--port", "$PortA", "--data-dir", "$da", "--debug" `
    -WindowStyle Hidden -RedirectStandardInput (Join-Path $tmp 'stdin_a.txt') `
    -RedirectStandardOutput $oa -RedirectStandardError $ea -PassThru
Start-Sleep -Seconds 5
Stop-Process -Id $pa.Id, $pb.Id -Force -ErrorAction SilentlyContinue

$bOut = if (Test-Path $ob) { Get-Content $ob -Raw } else { '（无 B 输出）' }
$bErr = if (Test-Path $eb) { Get-Content $eb -Raw } else { '（无 B 日志）' }

Write-Host ''
Write-Host '---- B 实例输出 ----'
Write-Host $bOut
Write-Host '---- B 网络日志 ----'
Write-Host $bErr

if ($bOut -match 'hello from A') {
    Write-Result "[PASS] 双实例联调成功：B 收到了 A 的消息。$bOut"
    exit 0
}
Write-Result "[FAIL] B 未收到 A 的消息。B.out=$bOut`nB.err=$bErr`n常见原因：防火墙未放行（请以管理员运行本脚本）。"
exit 1
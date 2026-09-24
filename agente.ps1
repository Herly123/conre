param(
  [switch]$Instalar,
  [switch]$Solicitar,
  [string]$Relay,
  [string]$Codigo
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Dir = 'C:\ProgramData\conexion-remota'
$CfgPath = Join-Path $Dir 'config.json'
$LogPath = Join-Path $Dir 'agente.log'
$CwdPath = Join-Path $Dir 'cwd.txt'

function Add-Log([string]$m) {
  $line = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') + ' ' + $m
  Add-Content -LiteralPath $LogPath -Value $line -ErrorAction SilentlyContinue
}

function Send-Json([string]$url, $obj, $token) {
  $json = $obj | ConvertTo-Json -Compress -Depth 8
  $bytes = [Text.Encoding]::UTF8.GetBytes($json)
  $headers = @{}
  if ($token) { $headers['x-device-token'] = $token }
  return Invoke-RestMethod -Uri $url -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers $headers -TimeoutSec 40
}

function New-Rsa([string]$xml) {
  $r = New-Object System.Security.Cryptography.RSACryptoServiceProvider
  $r.PersistKeyInCsp = $false
  $r.FromXmlString($xml)
  return $r
}

function Eq-Bytes([byte[]]$a, [byte[]]$b) {
  if ($null -eq $a -or $null -eq $b -or $a.Length -ne $b.Length) { return $false }
  $d = 0
  for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ($a[$i] -bxor $b[$i]) }
  return $d -eq 0
}

function Protect-Sobre([string]$xmlPub, $obj) {
  $json = $obj | ConvertTo-Json -Compress -Depth 8
  $plain = [Text.Encoding]::UTF8.GetBytes($json)
  $aesKey = New-Object byte[] 32
  $macKey = New-Object byte[] 32
  $iv = New-Object byte[] 16
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($aesKey)
  $rng.GetBytes($macKey)
  $rng.GetBytes($iv)
  $aes = [Security.Cryptography.Aes]::Create()
  $aes.KeySize = 256
  $aes.Mode = [Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $aesKey
  $aes.IV = $iv
  $enc = $aes.CreateEncryptor()
  $ct = $enc.TransformFinalBlock($plain, 0, $plain.Length)
  $macInput = New-Object byte[] ($iv.Length + $ct.Length)
  [Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
  [Buffer]::BlockCopy($ct, 0, $macInput, $iv.Length, $ct.Length)
  $hmac = New-Object System.Security.Cryptography.HMACSHA256
  $hmac.Key = $macKey
  $mac = $hmac.ComputeHash($macInput)
  $wrap = New-Object byte[] 64
  [Buffer]::BlockCopy($aesKey, 0, $wrap, 0, 32)
  [Buffer]::BlockCopy($macKey, 0, $wrap, 32, 32)
  $rsa = New-Rsa $xmlPub
  $ek = $rsa.Encrypt($wrap, $true)
  $rsa.Clear()
  return @{
    v = 1
    ek = [Convert]::ToBase64String($ek)
    iv = [Convert]::ToBase64String($iv)
    ct = [Convert]::ToBase64String($ct)
    mac = [Convert]::ToBase64String($mac)
  }
}

function Open-Sobre([string]$xmlPriv, $blob) {
  $rsa = New-Rsa $xmlPriv
  $keys = $rsa.Decrypt([Convert]::FromBase64String([string]$blob.ek), $true)
  $rsa.Clear()
  if ($keys.Length -ne 64) { throw 'llave invalida' }
  $aesKey = New-Object byte[] 32
  $macKey = New-Object byte[] 32
  [Buffer]::BlockCopy($keys, 0, $aesKey, 0, 32)
  [Buffer]::BlockCopy($keys, 32, $macKey, 0, 32)
  $iv = [Convert]::FromBase64String([string]$blob.iv)
  $ct = [Convert]::FromBase64String([string]$blob.ct)
  $mac = [Convert]::FromBase64String([string]$blob.mac)
  $macInput = New-Object byte[] ($iv.Length + $ct.Length)
  [Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
  [Buffer]::BlockCopy($ct, 0, $macInput, $iv.Length, $ct.Length)
  $hmac = New-Object System.Security.Cryptography.HMACSHA256
  $hmac.Key = $macKey
  $calc = $hmac.ComputeHash($macInput)
  if (-not (Eq-Bytes $mac $calc)) { throw 'MAC invalido' }
  $aes = [Security.Cryptography.Aes]::Create()
  $aes.Key = $aesKey
  $aes.IV = $iv
  $aes.Mode = [Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
  $dec = $aes.CreateDecryptor()
  $plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)
  return [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
}

function Test-Borrar([string]$cmd) {
  return $cmd -match '(?i)format-volume|format-disk|clear-disk|initialize-disk|remove-partition|diskpart|cipher\s+/w|format\s+[a-z]:|format\s+/fs'
}

function Test-Alto([string]$cmd) {
  return $cmd -match '(?i)shutdown|restart-computer|stop-computer|restart-service|stop-service|remove-item|\brm\s+|rmdir|\bdel\s+|erase\s+|rd\s+/s|reg\s+delete|net\s+user|net\s+localgroup|bcdedit|takeown|set-mppreference|schtasks|taskkill|stop-process|\bformat\b'
}

function Save-Cfg($cfg) {
  $json = $cfg | ConvertTo-Json -Depth 6
  $utf8 = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($CfgPath, $json, $utf8)
}

function Detener-Agente {
  try { schtasks /End /TN 'Conexion Remota' 2>$null | Out-Null } catch { }
  try {
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -OperationTimeoutSec 8 |
      Where-Object { $_.CommandLine -and $_.CommandLine -like '*conexion-remota*' -and $_.ProcessId -ne $PID } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  } catch { }
}

function Iniciar-Tarea {
  $tr = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\conexion-remota\agente.ps1'
  schtasks /Create /F /TN 'Conexion Remota' /SC MINUTE /MO 1 /RU SYSTEM /RL HIGHEST /TR $tr | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear la tarea programada' }
  schtasks /Run /TN 'Conexion Remota' | Out-Null
}

function Nueva-Llave {
  $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
  $rsa.PersistKeyInCsp = $false
  $pub = $rsa.ToXmlString($false)
  $priv = $rsa.ToXmlString($true)
  $rsa.Clear()
  return @{ pub = $pub; priv = $priv }
}

function Write-Cortar {
  @'
schtasks /Delete /TN "Conexion Remota" /F
Remove-Item -LiteralPath "C:\ProgramData\conexion-remota\config.json" -Force -ErrorAction SilentlyContinue
Write-Host "Conexion cortada en esta PC."
'@ | Set-Content -LiteralPath (Join-Path $Dir 'cortar.ps1') -Encoding ASCII
}

function Asegurar-Dir {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
  if (-not (Test-Path $CwdPath)) { Set-Content -LiteralPath $CwdPath -Value 'C:\' -Encoding ASCII }
}

function Install-Agente {
  Write-Host 'Instalando conexion remota...'
  Asegurar-Dir
  $llave = Nueva-Llave
  $reg = Send-Json ($Relay.TrimEnd('/') + '/api/registrar') @{
    codigo = $Codigo.ToUpper()
    pubkey = $llave.pub
    hostname = $env:COMPUTERNAME
    usuario = $env:USERNAME
  } $null
  $cfg = @{
    relay = $Relay.TrimEnd('/')
    id = $reg.id
    token = $reg.token
    opPubkey = $reg.opPubkey
    privateKeyXml = $llave.priv
  }
  Save-Cfg $cfg
  icacls $CfgPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
  Write-Cortar
  Detener-Agente
  Iniciar-Tarea
  Add-Log ('instalado ' + $env:COMPUTERNAME + ' ' + $reg.id)
  Write-Host ''
  Write-Host 'Listo. Esta PC quedo enlazada.'
  Write-Host 'Puedes cerrar esta ventana.'
  Write-Host 'Para cortar: powershell -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\conexion-remota\cortar.ps1'
}

function Install-Solicitar {
  Asegurar-Dir
  $llave = Nueva-Llave
  $reg = Send-Json ($Relay.TrimEnd('/') + '/api/solicitar') @{
    pubkey = $llave.pub
    hostname = $env:COMPUTERNAME
    usuario = $env:USERNAME
  } $null
  if (-not $reg.codigo) { throw 'No se pudo generar el codigo.' }
  $cfg = @{
    relay = $Relay.TrimEnd('/')
    id = $null
    token = $reg.token
    opPubkey = $null
    privateKeyXml = $llave.priv
  }
  Save-Cfg $cfg
  icacls $CfgPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
  Write-Cortar
  Detener-Agente
  Iniciar-Tarea
  Add-Log ('solicitud ' + $env:COMPUTERNAME + ' ' + $reg.codigo)
  Write-Host ''
  Write-Host '===================================================='
  Write-Host ('   TU CODIGO ES:  ' + $reg.codigo)
  Write-Host '===================================================='
  Write-Host ''
  Write-Host 'Enviaselo a la persona que te esta ayudando (WhatsApp).'
  Write-Host 'Cuando lo ingrese, la conexion queda lista sola.'
  Write-Host 'Deja esta PC encendida y con internet.'
  Write-Host ''
  Write-Host 'Puedes cerrar esta ventana.'
  Write-Host 'Para cortar: powershell -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\conexion-remota\cortar.ps1'
}

function Get-Cwd {
  if (Test-Path $CwdPath) {
    $p = (Get-Content -LiteralPath $CwdPath -Raw).Trim()
    if ($p) { return $p }
  }
  return 'C:\'
}

function Set-Cwd([string]$p) {
  Set-Content -LiteralPath $CwdPath -Value $p -Encoding ASCII
}

function Recortar([string]$s) {
  if ($null -eq $s) { return '' }
  if ($s.Length -le 200000) { return $s }
  return $s.Substring(0, 200000) + "`n... recortado ..."
}

function Invoke-Remoto([string]$cmd, [int]$timeout) {
  $cwd = Get-Cwd
  $ps = [powershell]::Create()
  $rs = [runspacefactory]::CreateRunspace()
  $rs.Open()
  $ps.Runspace = $rs
  try { $rs.SessionStateProxy.Path.SetLocation($cwd) } catch { }
  [void]$ps.AddScript($cmd)
  $h = $ps.BeginInvoke()
  if (-not $h.AsyncWaitHandle.WaitOne($timeout * 1000)) {
    $ps.Stop()
    $ps.Dispose()
    $rs.Close()
    return @{ ok = $false; salida = 'Tiempo agotado'; codigo = 124 }
  }
  $out = ''
  $ok = $true
  try {
    $col = $ps.EndInvoke($h)
    $out = ($col | Out-String)
    $nc = $rs.SessionStateProxy.Path.CurrentLocation.Path
    if ($nc) { Set-Cwd ([string]$nc) }
  } catch {
    $ok = $false
    $out = $_.Exception.Message
  }
  $errs = @($ps.Streams.Error | ForEach-Object { $_.ToString() })
  $ps.Dispose()
  $rs.Close()
  if ($errs.Count) {
    $out = ($out + "`n" + ($errs -join "`n"))
    $ok = $false
  }
  return @{ ok = [bool]$ok; salida = (Recortar $out); codigo = $(if ($ok) { 0 } else { 1 }) }
}

function Invoke-Trabajo($job) {
  $tipo = [string]$job.tipo
  if ($tipo -eq 'info') {
    $txt = "hostname=$env:COMPUTERNAME`nusuario=$env:USERNAME`ncwd=$(Get-Cwd)`nos=$([Environment]::OSVersion.VersionString)"
    return @{ ok = $true; salida = $txt }
  }
  if ($tipo -eq 'specs') {
    Add-Log 'specs'
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8
    $cs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 8
    $cpu = Get-CimInstance Win32_Processor -OperationTimeoutSec 8 | Select-Object -First 1
    $ramTotal = 0
    if ($cs.TotalPhysicalMemory) { $ramTotal = [math]::Round($cs.TotalPhysicalMemory / 1MB, 0) }
    $ramLibre = 0
    if ($os.FreePhysicalMemory) { $ramLibre = [math]::Round($os.FreePhysicalMemory / 1024, 0) }
    $discos = @()
    foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 8)) {
      $t = 0; $l = 0
      if ($d.Size) { $t = [math]::Round($d.Size / 1MB, 0) }
      if ($d.FreeSpace) { $l = [math]::Round($d.FreeSpace / 1MB, 0) }
      $discos += @{ letra = [string]$d.DeviceID; totalMB = $t; libreMB = $l }
    }
    $proc = @()
    foreach ($p in (Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10)) {
      $proc += @{ nombre = [string]$p.ProcessName; ramMB = [math]::Round($p.WorkingSet64 / 1MB, 1) }
    }
    $carga = 0
    if ($null -ne $cpu.LoadPercentage) { $carga = [int]$cpu.LoadPercentage }
    $up = 0
    try { $up = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) } catch { }
    $def = $null
    try {
      $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -OperationTimeoutSec 8 -ErrorAction Stop
      $def = @{ antivirus = (@($av).Count -gt 0) }
    } catch { }
    $obj = @{
      hostname       = $env:COMPUTERNAME
      usuario        = $env:USERNAME
      os             = [string]$os.Caption
      version        = [string]$os.Version
      arquitectura   = [string]$os.OSArchitecture
      cpu            = [string]$cpu.Name
      nucleos        = [int]$cpu.NumberOfCores
      hilos          = [int]$cpu.NumberOfLogicalProcessors
      cargaCPU       = $carga
      ramTotalMB     = $ramTotal
      ramLibreMB     = $ramLibre
      discos         = $discos
      uptimeHoras    = $up
      ultimoArranque = [string]$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
      procesos       = $proc
      defensor       = $def
      fecha          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
    return @{ ok = $true; salida = ($obj | ConvertTo-Json -Compress -Depth 8) }
  }
  if ($tipo -eq 'listar') {
    $ruta = [string]$job.ruta
    if (-not $ruta) { $ruta = Get-Cwd }
    $items = Get-ChildItem -Force -LiteralPath $ruta | ForEach-Object {
      '{0}  {1,12}  {2}  {3}' -f $_.Mode, $_.Length, $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.Name
    }
    return @{ ok = $true; salida = ($items -join "`n") }
  }
  if ($tipo -eq 'leer') {
    $ruta = [string]$job.ruta
    $offset = [int64]$job.offset
    $largo = [int]$job.largo
    if ($largo -le 0 -or $largo -gt 1048576) { $largo = 1048576 }
    $fs = [IO.File]::Open($ruta, 'Open', 'Read', 'ReadWrite')
    try {
      $total = $fs.Length
      if ($offset -gt $total) { $offset = $total }
      [void]$fs.Seek($offset, 'Begin')
      $buf = New-Object byte[] $largo
      $n = $fs.Read($buf, 0, $largo)
      $slice = New-Object byte[] $n
      if ($n -gt 0) { [Buffer]::BlockCopy($buf, 0, $slice, 0, $n) }
      return @{ ok = $true; datos = [Convert]::ToBase64String($slice); n = $n; total = [string]$total }
    } finally { $fs.Close() }
  }
  if ($tipo -eq 'escribir' -or $tipo -eq 'anexar') {
    if (-not $job.confirmarAlto) { return @{ ok = $false; salida = 'escritura sin confirmacion' } }
    $ruta = [string]$job.ruta
    $parent = Split-Path -Parent $ruta
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
      New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $bytes = New-Object byte[] 0
    if ($job.datos) { $bytes = [Convert]::FromBase64String([string]$job.datos) }
    $mode = 'Create'
    if ($tipo -eq 'anexar') { $mode = 'Append' }
    $fs = [IO.File]::Open($ruta, $mode, 'Write', 'Read')
    try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Close() }
    return @{ ok = $true; salida = "escrito $($bytes.Length)" }
  }
  if ($tipo -eq 'shell') {
    $cmd = [string]$job.cmd
    if ((Test-Borrar $cmd) -and -not $job.confirmarBorrado) {
      return @{ ok = $false; salida = 'comando destructivo bloqueado: hace falta confirmacion BORRAR' }
    }
    if ((Test-Alto $cmd) -and -not $job.confirmarAlto -and -not $job.confirmarBorrado) {
      return @{ ok = $false; salida = 'comando de nivel alto bloqueado: hace falta confirmacion SI' }
    }
    $timeout = 120
    if ($job.timeout) { $timeout = [int]$job.timeout }
    if ($timeout -lt 5) { $timeout = 5 }
    if ($timeout -gt 300) { $timeout = 300 }
    Add-Log ('shell ' + $cmd.Substring(0, [Math]::Min(120, $cmd.Length)))
    return Invoke-Remoto $cmd $timeout
  }
  if ($tipo -eq 'cortar') {
    Add-Log 'cortar'
    schtasks /Delete /TN 'Conexion Remota' /F | Out-Null
    $script:PedirSalir = $true
    return @{ ok = $true; salida = 'cortado' }
  }
  return @{ ok = $false; salida = 'tipo desconocido' }
}

if ($Instalar) {
  Install-Agente
  exit 0
}

if ($Solicitar) {
  Install-Solicitar
  exit 0
}

$mutex = New-Object System.Threading.Mutex($false, 'Global\ConexionRemotaAgente')
if (-not $mutex.WaitOne(0)) { exit 0 }

if (-not (Test-Path $CfgPath)) {
  Add-Log 'sin config'
  exit 1
}

$raw = Get-Content -LiteralPath $CfgPath -Raw -Encoding UTF8
$cfg = $raw | ConvertFrom-Json
Add-Log ('agente arriba ' + $cfg.id)

$script:UltimaUrl = (Get-Date).AddMinutes(-10)

while ($true) {
  try {
    if (((Get-Date) - $script:UltimaUrl).TotalSeconds -ge 45) {
      $script:UltimaUrl = Get-Date
      try {
        $u = [string](Invoke-RestMethod -TimeoutSec 10 -Uri 'https://raw.githubusercontent.com/Herly123/conre/main/relay.txt')
        $u = $u.Trim()
        if ($u -match '^https?://' -and $u -ne $cfg.relay) {
          $cfg.relay = $u
          Save-Cfg $cfg
          Add-Log ('relay actualizado ' + $u)
        }
      } catch { }
    }
    $poll = Send-Json ($cfg.relay + '/api/poll') @{} $cfg.token
    if ($poll.opPubkey -and -not $cfg.opPubkey) {
      $cfg.opPubkey = $poll.opPubkey
      Save-Cfg $cfg
      Add-Log 'vinculado'
    }
    if ($poll.pendiente -and -not $cfg.opPubkey) {
      Start-Sleep -Seconds 3
      continue
    }
    if ($poll.jobs -and $cfg.opPubkey) {
      foreach ($job in @($poll.jobs)) {
        $plain = Open-Sobre $cfg.privateKeyXml $job.blob
        $script:PedirSalir = $false
        $res = Invoke-Trabajo $plain
        $blob = Protect-Sobre $cfg.opPubkey $res
        Send-Json ($cfg.relay + '/api/resultado') @{ id = $job.id; blob = $blob } $cfg.token | Out-Null
        if ($script:PedirSalir) {
          Remove-Item -LiteralPath $CfgPath -Force -ErrorAction SilentlyContinue
          exit 0
        }
      }
    } else {
      Start-Sleep -Seconds 2
    }
  } catch {
    Add-Log $_.Exception.Message
    $script:UltimaUrl = (Get-Date).AddMinutes(-10)
    Start-Sleep -Seconds 5
  }
}

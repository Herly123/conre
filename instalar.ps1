# Version simple que sirve el relay en la raiz.
# El relay reemplaza __RELAY__ por su direccion al servir este archivo.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RelayPorDefecto = '__RELAY__'

function Titulo {
  Write-Host ''
  Write-Host '===================================================='
  Write-Host '  CONEXION REMOTA'
  Write-Host '===================================================='
  Write-Host '  Quien te esta ayudando podra usar la terminal y'
  Write-Host '  leer o editar archivos de esta PC.'
  Write-Host '  La comunicacion va cifrada. Esta PC no abre puertos.'
  Write-Host ''
}

function Traer-Agente([string]$relay) {
  $dir = 'C:\ProgramData\conexion-remota'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Write-Host 'Preparando el agente...'
  $destino = $dir + '\agente.ps1'
  Remove-Item -LiteralPath $destino -Force -ErrorAction SilentlyContinue
  $fuentes = @(
    'https://raw.githubusercontent.com/Herly123/conre/main/agente.ps1',
    ($relay.TrimEnd('/') + '/agente.ps1')
  )
  $bajado = $false
  $detalle = ''
  foreach ($u in $fuentes) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $destino
      $bajado = $true
      break
    } catch { $detalle = $_.Exception.Message }
  }
  if (-not $bajado) {
    try {
      & curl.exe -sL -o $destino $fuentes[0]
      if ((Test-Path -LiteralPath $destino) -and ((Get-Item -LiteralPath $destino).Length -gt 1000)) { $bajado = $true }
    } catch { $detalle = $detalle + ' | curl: ' + $_.Exception.Message }
  }
  if (-not $bajado) { throw ('No se pudo descargar el agente. Detalle: ' + $detalle) }
  return $destino
}

Titulo

Write-Host 'Si ya te pasaron un codigo, pegalo y presiona Enter.'
Write-Host 'Si NO tienes codigo, presiona solo Enter: esta PC generara uno'
Write-Host 'para que se lo envies a quien te esta ayudando.'
Write-Host ''
$Codigo = (Read-Host 'Codigo (o Enter para generar)').Trim()

if (-not $RelayPorDefecto.StartsWith('http')) {
  try {
    $RelayPorDefecto = [string](Invoke-RestMethod -TimeoutSec 15 -Uri 'https://raw.githubusercontent.com/Herly123/conre/main/relay.txt')
    $RelayPorDefecto = $RelayPorDefecto.Trim()
  } catch { }
}

if (-not $RelayPorDefecto.StartsWith('http')) {
  Write-Host 'No hay servidor configurado en este instalador.'
  Read-Host 'Presiona Enter para cerrar'
  exit 1
}

$relay = $RelayPorDefecto.TrimEnd('/')
$ps1 = Traer-Agente $relay

if ($Codigo) {
  & $ps1 -Instalar -Relay $relay -Codigo $Codigo.ToUpper()
} else {
  & $ps1 -Solicitar -Relay $relay
}

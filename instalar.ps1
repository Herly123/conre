# Version simple que sirve el relay en la raiz.
# El relay reemplaza https://shelf-lending-ask-joshua.trycloudflare.com por su direccion al servir este archivo.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RelayPorDefecto = 'https://shelf-lending-ask-joshua.trycloudflare.com'

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
  try {
    Invoke-WebRequest -UseBasicParsing -Uri ($relay.TrimEnd('/') + '/agente.ps1') -OutFile ($dir + '\agente.ps1')
  } catch {
    throw 'No se pudo descargar el agente. Revisa la conexion a internet.'
  }
  return ($dir + '\agente.ps1')
}

Titulo

Write-Host 'Si ya te pasaron un codigo, pegalo y presiona Enter.'
Write-Host 'Si NO tienes codigo, presiona solo Enter: esta PC generara uno'
Write-Host 'para que se lo envies a quien te esta ayudando.'
Write-Host ''
$Codigo = (Read-Host 'Codigo (o Enter para generar)').Trim()

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

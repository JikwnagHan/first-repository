# RanSim_Installer_Only_v_0.4c_with_Atomic_Caldera.ps1
# RanSim 설치/검증 자동화 스크립트 (v_0.4c)
# 작성자: ChatGPT (초안)
# 설명:
#  - RanSim 설치 확인 및 설치(오프라인/URL/수동 선택)
#  - 서명 검증(Authenticode) 수행 (발행사에 KnowBe4 포함 여부 검사)
#  - 설치 진행 후 검증(레지스트리/프로그램 폴더/시작메뉴) 및 적절한 로그 남김
#  - Atomic/Caldera 설치 여부 체크(선택, 자동 설치는 안전상의 이유로 묻고 진행)
# 사용법 (관리자 PowerShell에서 실행):
#  .\RanSim_Installer_Only_v_0.4c_with_Atomic_Caldera.ps1 [-InstallerPath "C:\path\SimulatorSetup.exe"] [-InstallerUrl "https://..."] [-Quiet]
# 주의: 관리자 권한으로 실행하세요. VM에서 테스트 권장.

param(
  [string]$InstallerPath,
  [string]$InstallerUrl,
  [switch]$Quiet,
  [string]$LogRoot = "C:\Logs\RanSim"
)

# 한글 주석: 안전을 위해 많은 동작(다운로드, 설치)은 사용자 확인을 거칩니다.
# 한글 주석: PowerShell 5.1 호환성을 유지합니다.

function New-LogWriter {
  param([string]$Root)
  $logDir = Join-Path $Root "Logs"
  if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
  }
  $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $log = Join-Path $logDir ("RanSim_install_{0}.log" -f $stamp)
  New-Item -ItemType File -Path $log -Force | Out-Null
  return $log
}

function Write-Log {
  param([string]$Path,[string]$Level,[string]$Message)
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  Write-Host $line
  for ($i = 0; $i -lt 3; $i++) {
    try {
      Add-Content -LiteralPath $Path -Value $line -ErrorAction Stop
      break
    } catch {
      Start-Sleep -Milliseconds 150
      if ($i -eq 2) {
        Write-Warning "로그 쓰기 실패: $($_.Exception.Message)"
      }
    }
  }
}

function Test-UrlReachable {
  param([string]$Url, [int]$TimeoutMs = 5000)
  try {
    $req = [System.Net.WebRequest]::Create($Url)
    $req.Method = "HEAD"
    $req.Timeout = $TimeoutMs
    $resp = $req.GetResponse()
    if ($resp -ne $null) {
      $resp.Close()
      return $true
    }
    return $false
  } catch {
    return $false
  }
}

function Download-File {
  param([string]$Url, [string]$Dest)
  try {
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($Url, $Dest)
    return (Test-Path -LiteralPath $Dest)
  } catch {
    return $false
  }
}

function Test-Signature-KnowBe4 {
  param([string]$FilePath)
  if (-not (Test-Path -LiteralPath $FilePath)) { return $false }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    $statusOk = ($sig.Status -eq 'Valid')
    $pubOk = $false
    if ($sig.SignerCertificate -ne $null) {
      $sub = $sig.SignerCertificate.Subject
      $iss = $sig.SignerCertificate.Issuer
      if ($sub -and $sub -match "KnowBe4") { $pubOk = $true }
      if (-not $pubOk -and $iss -and $iss -match "KnowBe4") { $pubOk = $true }
    }
    return ($statusOk -and $pubOk)
  } catch {
    return $false
  }
}

function Find-LocalInstaller {
  # 다운로드/바탕화면/TEMP 폴더에서 후보 파일 검색
  $roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP")
  $patterns = @("SimulatorSetup*.exe","ransim-setup*.exe","RanSim*.exe","RanSim*.msi","SimulatorSetup*.msi")
  foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    foreach ($pat in $patterns) {
      $hit = Get-ChildItem -LiteralPath $root -Filter $pat -File -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
      if ($hit) { return $hit.FullName }
    }
  }
  return $null
}

function Get-QuietArgs {
  param([string]$InstallerPath)
  $ext = [IO.Path]::GetExtension($InstallerPath).ToLowerInvariant()
  if ($ext -eq ".msi") { return "/qn /norestart" }
  # 공통 EXE 스위치 후보 (설치파일마다 상이)
  return "/S"
}

function Verify-Installed {
  # RanSim 흔적을 레지스트리/프로그램 폴더/시작메뉴에서 검색
  $hits = @()
  $regRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
  )
  foreach ($rr in $regRoots) {
    if (-not (Test-Path -LiteralPath $rr)) { continue }
    Get-ChildItem $rr -ErrorAction SilentlyContinue | ForEach-Object {
      $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
      if ($props -ne $null) {
        $dn = $props.DisplayName
        $pub = $props.Publisher
        if ($dn -and $dn -match "RanSim") { $hits += "REG:$($props.DisplayName)" }
        if ($pub -and $pub -match "KnowBe4") { $hits += "REGPUB:$($props.DisplayName)" }
      }
    }
  }

  $pf64 = ${env:ProgramFiles(x86)}
  if (-not $pf64) { $pf64 = $env:ProgramFiles }
  $candidates = @(
    (Join-Path $pf64 "KnowBe4\RanSim"),
    (Join-Path $pf64 "KnowBe4\Ransomware Simulator"),
    (Join-Path $pf64 "RanSim")
  )
  foreach ($f in $candidates) {
    if ($f -and (Test-Path -LiteralPath $f)) { $hits += "DIR:$f" }
  }

  $startMenu = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
  if (Test-Path -LiteralPath $startMenu) {
    $lnks = Get-ChildItem -LiteralPath $startMenu -Filter "RanSim*.lnk" -Recurse -ErrorAction SilentlyContinue
    if ($lnks -and $lnks.Count -gt 0) { $hits += "LNK:$($lnks[0].FullName)" }
  }

  return ,$hits
}

function Prompt-For-File {
  # 파일 선택 다이얼로그 (GUI). 콘솔 환경에서는 대화형 입력으로 폴백.
  Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
  try {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = "RanSim 설치 파일 선택"
    $ofd.Filter = "Executable files (*.exe;*.msi)|*.exe;*.msi|All files (*.*)|*.*"
    $ofd.InitialDirectory = "$env:USERPROFILE\Downloads"
    if ($ofd.ShowDialog() -eq "OK") { return $ofd.FileName }
  } catch {
    Write-Host "GUI 선택 불가(원인): $($_.Exception.Message)"
  }
  # 콘솔 입력 폴백
  $input = Read-Host "설치 파일 경로를 입력하세요 (예: Y:\SimulatorSetup.exe)"
  if ($input -and (Test-Path -LiteralPath $input)) { return (Resolve-Path -LiteralPath $input).Path }
  return $null
}

function Wait-For-Install {
  param([int]$TimeoutSec = 120, [int]$PollSec = 5, [string]$Log)
  $elapsed = 0
  while ($elapsed -lt $TimeoutSec) {
    $found = Verify-Installed
    if ($found -and $found.Count -gt 0) {
      Write-Log -Path $Log -Level "INFO" -Message ("설치 신호 감지 → {0}" -f ($found -join "; "))
      return $true
    }
    Start-Sleep -Seconds $PollSec
    $elapsed += $PollSec
    Write-Log -Path $Log -Level "INFO" -Message ("설치 신호 대기 중... {0}/{1}초" -f $elapsed, $TimeoutSec)
  }
  return $false
}

# -------------------- 실행 시작 --------------------
if (-not (Test-Path -LiteralPath $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
$log = New-LogWriter -Root $LogRoot
Write-Log -Path $log -Level "INFO" -Message "RanSim 설치/검증 시작"
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$psv = $PSVersionTable.PSVersion.ToString()
Write-Log -Path $log -Level "INFO" -Message ("OS: {0}  PowerShell: {1}" -f $os, $psv)
Write-Log -Path $log -Level "INFO" -Message ("로그 경로: {0}" -f $log)

# 1) 이미 설치되어 있는지 확인
$existing = Verify-Installed
if ($existing -and $existing.Count -gt 0) {
  Write-Log -Path $log -Level "INFO" -Message "이미 RanSim이 설치되어 있습니다. 설치 단계를 건너뜁니다."
  Write-Host "[OK] RanSim 설치가 확인되었습니다."
} else {
  Write-Log -Path $log -Level "WARN" -Message "RanSim 미설치 확인. 설치 파일 확보를 시도합니다."
  # 2) 입력값/로컬 검색/URL 후보 확인
  $installer = $null
  if ($InstallerPath -and (Test-Path -LiteralPath $InstallerPath)) {
    $installer = (Resolve-Path -LiteralPath $InstallerPath).Path
    Write-Log -Path $log -Level "INFO" -Message ("InstallerPath 사용: {0}" -f $installer)
  } elseif ($InstallerUrl) {
    Write-Log -Path $log -Level "INFO" -Message ("InstallerUrl 사용: {0}" -f $InstallerUrl)
  } else {
    Write-Log -Path $log -Level "INFO" -Message "로컬 폴더에서 설치 파일 탐색 시도"
    $local = Find-LocalInstaller
    if ($local) {
      Write-Log -Path $log -Level "INFO" -Message ("로컬 설치 파일 발견: {0}" -f $local)
      $installer = $local
    } else {
      Write-Log -Path $log -Level "INFO" -Message "후보 URL(빠른 점검) 확인"
      $candidates = @(
        "https://downloads.knowbe4.com/ransim/ransim-setup.exe",
        "https://downloads.knowbe4.com/ransim/SimulatorSetup.exe",
        "https://downloads.knowbe4.com/ransim/ransim-setup-latest.exe"
      )
      $good = $null
      foreach ($u in $candidates) {
        if (Test-UrlReachable -Url $u -TimeoutMs 3000) {
          $good = $u; break
        }
      }
      if ($good) {
        Write-Log -Path $log -Level "INFO" -Message ("온라인 설치 파일 확인: {0}" -f $good)
        $InstallerUrl = $good
      } else {
        Write-Log -Path $log -Level "WARN" -Message "설치 파일을 자동으로 찾지 못했습니다. 파일 선택 창 또는 콘솔 입력을 진행합니다."
        $selected = Prompt-For-File
        if ($selected) {
          $installer = $selected
          Write-Log -Path $log -Level "INFO" -Message ("사용자 지정 설치 파일: {0}" -f $installer)
        }
      }
    }
  }

  # 3) URL에서 다운로드
  if (-not $installer -and $InstallerUrl) {
    $dest = Join-Path $env:TEMP ("RanSimInstaller_{0}.exe" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    Write-Log -Path $log -Level "INFO" -Message ("다운로드 시도: {0}" -f $InstallerUrl)
    if (Download-File -Url $InstallerUrl -Dest $dest) {
      $installer = $dest
      Write-Log -Path $log -Level "INFO" -Message ("다운로드 완료: {0}" -f $installer)
    } else {
      Write-Log -Path $log -Level "ERROR" -Message "다운로드 실패"
    }
  }

  if (-not $installer) {
    Write-Log -Path $log -Level "ERROR" -Message "설치 파일 확보 실패: InstallerPath 또는 InstallerUrl을 지정해 주세요."
    throw "InstallerNotFound"
  }

  # 4) 디지털 서명 확인 (권장)
  $sigOk = Test-Signature-KnowBe4 -FilePath $installer
  if (-not $sigOk) {
    Write-Log -Path $log -Level "WARN" -Message ("서명 검증 실패 또는 발행사 미일치: {0}" -f $installer)
    $ans = Read-Host "서명 검증 실패. 계속 진행하시겠습니까? (Y/N)"
    if ($ans -ne "Y" -and $ans -ne "y") {
      Write-Log -Path $log -Level "ERROR" -Message "사용자 중단: 서명 미검증"
      throw "SignatureInvalid"
    }
  } else {
    Write-Log -Path $log -Level "INFO" -Message "서명 검증 통과(발행사: KnowBe4, Status: Valid)"
  }

  # 5) 설치 실행
  $quietArgs = Get-QuietArgs -InstallerPath $installer
  if ($Quiet) {
    Write-Log -Path $log -Level "INFO" -Message ("조용한 모드 시도: {0} {1}" -f $installer, $quietArgs)
    try {
      $p = Start-Process -FilePath $installer -ArgumentList $quietArgs -PassThru -Wait -ErrorAction Stop
      Write-Log -Path $log -Level "INFO" -Message ("설치 프로세스 종료 코드: {0}" -f $p.ExitCode)
    } catch {
      Write-Log -Path $log -Level "WARN" -Message ("조용한 설치 실패: {0}" -f $_.Exception.Message)
      Write-Log -Path $log -Level "INFO" -Message "대화형 설치로 폴백합니다."
      Start-Process -FilePath $installer
      Write-Log -Path $log -Level "INFO" -Message "설치 마법사 완료 후 엔터 키를 눌러 계속하세요."
      Read-Host "설치 완료 후 엔터를 누르세요."
    }
  } else {
    Write-Log -Path $log -Level "INFO" -Message ("대화형 설치 실행: {0}" -f $installer)
    Start-Process -FilePath $installer
    Write-Log -Path $log -Level "INFO" -Message "설치 마법사 완료 후 엔터 키를 눌러 계속하세요."
    Read-Host "설치 완료 후 엔터를 누르세요."
  }

  # 6) 설치 검증 (폴링)
  $ok = Wait-For-Install -TimeoutSec 180 -PollSec 5 -Log $log
  if ($ok) {
    $found = Verify-Installed
    Write-Log -Path $log -Level "INFO" -Message ("설치 확인 OK → {0}" -f ($found -join "; "))
    Write-Host "[OK] RanSim 설치가 확인되었습니다."
  } else {
    Write-Log -Path $log -Level "ERROR" -Message "설치 확인 실패: RanSim 흔적을 찾지 못했습니다."
    throw "InstallVerifyFailed"
  }
}

# 7) Atomic/Caldera 설치 여부 체크 (선택적 안내)
Write-Log -Path $log -Level "INFO" -Message "Atomic Red Team / Caldera 설치 여부 확인"
# Atomic (Invoke-AtomicRedTeam 모듈) 체크
try {
  $mod = Get-Module -ListAvailable -Name Invoke-AtomicRedTeam -ErrorAction SilentlyContinue
  if ($mod) {
    Write-Log -Path $log -Level "INFO" -Message "Atomic Red Team 모듈 설치됨"
  } else {
    Write-Log -Path $log -Level "INFO" -Message "Atomic Red Team 미설치(권장: 설치하여 테스트 확장 가능)"
  }
} catch {
  Write-Log -Path $log -Level "WARN" -Message "Atomic 체크 중 예외: $($_.Exception.Message)"
}

# Caldera 체크 (Docker 기반 권장)
try {
  $docker = Get-Command -Name docker -ErrorAction SilentlyContinue
  if ($docker) {
    Write-Log -Path $log -Level "INFO" -Message "Docker CLI 발견. Caldera 자동 설치 가능."
  } else {
    Write-Log -Path $log -Level "INFO" -Message "Docker 미발견: Caldera 설치는 격리된 VM/서버에 Docker로 설치 권장"
  }
} catch {
  Write-Log -Path $log -Level "WARN" -Message "Caldera 체크 중 예외: $($_.Exception.Message)"
}

Write-Log -Path $log -Level "INFO" -Message "RanSim 설치/검증 스크립트 종료"

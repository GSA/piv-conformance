[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [switch] $SkipBuild,
    [switch] $SmokeTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$PreviousJavaHome = $env:JAVA_HOME
$Version = (Get-Content "$RepositoryRoot\tools\85b-swing-gui\src\main\resources\build.version" -Raw).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+(-rc\d+)?$') { throw "Invalid version: $Version" }
foreach ($Module in @("cardlib", "conformancelib")) {
    if ((Get-Content "$RepositoryRoot\$Module\src\main\resources\build.version" -Raw).Trim() -ne $Version) {
        throw "$Module version does not match the GUI."
    }
}

# Use the same checksum-pinned, patched Java 17 build for compilation and the runtime.
$RuntimeVersion = "17.0.21.0.11"
$RuntimeUrl = "https://corretto.aws/downloads/resources/17.0.21.0.11/amazon-corretto-17.0.21.0.11-windows-x64-jdk.zip"
$RuntimeHash = "59d6514305f6fab3b18955fb17185562f0a0bbf20e1466eda33a5429f3b31618"
$Cache = Join-Path $RepositoryRoot "build\toolchains"
New-Item -ItemType Directory -Path $Cache -Force | Out-Null
$RuntimeArchive = Join-Path $Cache "corretto-$RuntimeVersion-windows-x64-jdk.zip"
if (-not (Test-Path -LiteralPath $RuntimeArchive)) {
    Invoke-WebRequest -Uri $RuntimeUrl -OutFile $RuntimeArchive
}
if ((Get-FileHash $RuntimeArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $RuntimeHash) {
    throw "Corretto archive checksum mismatch. Remove $RuntimeArchive and retry."
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepositoryRoot ("build\releases\windows-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ"))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Choose a new output directory: $OutputDirectory" }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$Work = Join-Path $RepositoryRoot ("build\windows-package-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Work | Out-Null
try {
    Expand-Archive -LiteralPath $RuntimeArchive -DestinationPath "$Work\jdk"
    $Jdk = @(Get-ChildItem "$Work\jdk" -Directory)
    if ($Jdk.Count -ne 1) { throw "Unexpected JDK archive layout." }
    $Jdk = $Jdk[0].FullName
    $Release = Get-Content "$Jdk\release" -Raw
    if ($Release -notmatch '(?m)^JAVA_VERSION="17\.0\.21"\r?$' -or
        $Release -notmatch '(?m)^IMPLEMENTOR_VERSION="Corretto-17\.0\.21\.0\.11"\r?$' -or
        $Release -notmatch '(?m)^OS_NAME="Windows"\r?$' -or
        $Release -notmatch '(?m)^OS_ARCH="(x86_64|amd64)"\r?$') {
        throw "Expected Corretto $RuntimeVersion for Windows x64."
    }
    $env:JAVA_HOME = $Jdk
    if (-not $SkipBuild) { & "$PSScriptRoot\build-application.ps1" }

    # Keep every module, including dynamic crypto and PC/SC providers. Omit development archives.
    $Runtime = "$Work\runtime"
    & "$Jdk\bin\jlink.exe" --module-path "$Jdk\jmods" --add-modules ALL-MODULE-PATH `
        --output $Runtime --strip-debug --no-header-files --no-man-pages --compress=2
    if ($LASTEXITCODE -ne 0) { throw "Runtime image creation failed." }
    $ExpectedModules = @(Get-ChildItem "$Jdk\jmods\*.jmod" | ForEach-Object { $_.BaseName } | Sort-Object)
    $ActualModules = @(& "$Runtime\bin\java.exe" --list-modules | ForEach-Object { ($_ -split '@')[0] } | Sort-Object)
    if ($LASTEXITCODE -ne 0 -or @(Compare-Object $ExpectedModules $ActualModules).Count -ne 0) {
        throw "The runtime must retain every module from the pinned JDK."
    }
    foreach ($Notice in @("LICENSE", "ADDITIONAL_LICENSE_INFO", "ASSEMBLY_EXCEPTION", "README.md")) {
        Copy-Item "$Jdk\$Notice" $Runtime
    }
    if (-not (Test-Path "$Runtime\legal\java.base\LICENSE")) { throw "Runtime license is missing." }
    foreach ($SecurityFile in @("cacerts", "blocked.certs")) {
        if ((Get-FileHash "$Runtime\lib\security\$SecurityFile").Hash -ne
            (Get-FileHash "$Jdk\lib\security\$SecurityFile").Hash) {
            throw "Runtime security data differs from the patched vendor archive: $SecurityFile"
        }
    }
    # OpenJDK's eMudhra guidance requires removal of these roots; do not modify the vendor store.
    $TrustListing = & "$Runtime\bin\keytool.exe" -list -cacerts -storepass changeit -v 2>&1
    if ($LASTEXITCODE -ne 0 -or ($TrustListing -join "`n") -match
        '(?m)CN=(emSign ECC Root CA - G3|AAA Certificate Services|emSign Root CA - G1|emSign Root CA - G2)(,|\r?$)') {
        throw "Bundled runtime trust store does not satisfy the reviewed OpenJDK CA-compromise check."
    }
    Write-Host "Runtime verified: Corretto $RuntimeVersion, $($ActualModules.Count) modules, patched security data."
    $InputDirectory = New-Item -ItemType Directory -Path "$Work\input"
    $Jar = "gov.gsa.pivconformance.gui-$Version-shadow.jar"
    Copy-Item "$RepositoryRoot\tools\85b-swing-gui\build\libs\$Jar" $InputDirectory
    Copy-Item "$RepositoryRoot\cardlib\src\main\resources\user_log_config.xml" $InputDirectory
    Copy-Item "$RepositoryRoot\conformancelib\src\main\resources\pdval.properties" $InputDirectory
    Copy-Item "$RepositoryRoot\tools\85b-swing-gui\src\main\resources\build.version" $InputDirectory
    foreach ($Profile in @("PIV_Production_Cards", "PIV_ICAM_Test_Cards", "PIV-I_Production_Cards", "PIV-I_ICAM_Test_Cards")) {
        Copy-Item "$RepositoryRoot\conformancelib\testdata\$Profile.db" $InputDirectory
    }
    $Trust = "$RepositoryRoot\conformancelib\src\main\resources\x509-certs"
    if ((Get-FileHash "$Trust\cacerts.jks" -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        "41496e64cb241c8f98bebee33ff2f1f98530d4febc2ab0b9d369910578628a10") {
        throw "Trust store differs from the reviewed v1.0.9 baseline."
    }
    New-Item -ItemType Directory -Path "$InputDirectory\x509-certs\valid" -Force | Out-Null
    Copy-Item "$Trust\cacerts.jks" "$InputDirectory\x509-certs"
    Copy-Item "$Trust\valid\policy.xml", "$Trust\valid\valid.zip" "$InputDirectory\x509-certs\valid"
    & "$Jdk\bin\jpackage.exe" --type app-image --name CCT --dest "$Work\image" `
        --input $InputDirectory.FullName --main-jar $Jar --runtime-image $Runtime `
        --app-version ($Version.Split('-')[0]) --vendor "General Services Administration" `
        --description "PIV Card Conformance Tool" --java-options "-Dcct.packaged=true" `
        --icon "$RepositoryRoot\tools\85b-swing-gui\src\main\resources\icons\gsa.ico"
    if ($LASTEXITCODE -ne 0) { throw "jpackage failed." }
    $Image = "$Work\image\CCT"
    Copy-Item "$RepositoryRoot\docs\USER_GUIDE.md", "$RepositoryRoot\LICENSE.md" $Image
    (Get-Content "$PSScriptRoot\README.txt" -Raw).Replace("{{VERSION}}", $Version) |
        Set-Content "$Image\README.txt" -Encoding UTF8
    $Commit = $env:CCT_GIT_COMMIT
    if (-not $Commit) {
        $Commit = & git -C $RepositoryRoot rev-parse HEAD
        if ($LASTEXITCODE -ne 0) { throw "Set CCT_GIT_COMMIT when building a source archive." }
    }
    @("CCT $Version", "Platform: Windows x64", "Source commit: $Commit",
      "Bundled runtime: Amazon Corretto $RuntimeVersion", "Runtime modules: $($ActualModules.Count) (all vendor modules)",
      "Runtime archive: $RuntimeUrl",
      "Runtime archive SHA-256: $RuntimeHash") | Set-Content "$Image\BUILD-INFO.txt" -Encoding UTF8
    $Zip = Join-Path $OutputDirectory "piv-conformance-v$Version-windows-x64.zip"
    Compress-Archive -Path "$Image\*" -DestinationPath $Zip -CompressionLevel Optimal
    $Hash = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $([IO.Path]::GetFileName($Zip))" | Set-Content "$Zip.sha256" -Encoding ASCII

    # Verify the bytes clients will extract, including paths containing spaces.
    $Expanded = "$Work\CCT extracted package"
    Expand-Archive -LiteralPath $Zip -DestinationPath $Expanded
    foreach ($File in @("CCT.exe", "README.txt", "USER_GUIDE.md", "LICENSE.md", "BUILD-INFO.txt",
            "runtime\bin\java.exe", "runtime\bin\server\jvm.dll", "runtime\legal\java.base\LICENSE", "app\$Jar")) {
        if (-not (Test-Path "$Expanded\$File" -PathType Leaf)) { throw "ZIP is missing $File" }
    }
    & "$Expanded\runtime\bin\java.exe" -version
    if ($LASTEXITCODE -ne 0) { throw "Bundled Java did not start." }
    if ($SmokeTest) {
        $TestClasses = "$RepositoryRoot\tools\85b-swing-gui\build\classes\java\test"
        $RegressionClasses = "$RepositoryRoot\conformancelib\build\classes\java\test"
        foreach ($Bc in @("false", "true")) {
            & "$Expanded\runtime\bin\java.exe" "-Dcct.repository=$RepositoryRoot" "-Dcct.regressionBC=$Bc" `
                -cp "$TestClasses;$RegressionClasses;$Expanded\app\$Jar" `
                gov.gsa.pivconformance.gui.ReaderAndVersionRegressionTest "$Expanded\app" "$Work\data-$Bc"
            if ($LASTEXITCODE -ne 0) { throw "Bundled-runtime regression failed (BC=$Bc)." }
        }
        $PreviousPath = $env:PATH; $PreviousJava = $env:JAVA_HOME; $PreviousData = $env:LOCALAPPDATA
        $Process = $null
        try {
            $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
            $env:JAVA_HOME = "$Work\no-system-java"
            $env:LOCALAPPDATA = "$Work\fresh-user"
            $Executable = "$Expanded\CCT.exe"
            $Process = Start-Process $Executable -WorkingDirectory $env:TEMP -PassThru `
                -RedirectStandardOutput "$OutputDirectory\native-launch.stdout.log" `
                -RedirectStandardError "$OutputDirectory\native-launch.stderr.log"
            $Deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 500
                # jpackage may use a child launcher process; require its actual application window.
                $Windows = @(Get-Process -Name CCT -ErrorAction SilentlyContinue | Where-Object {
                    $_.Path -eq $Executable -and $_.MainWindowTitle -eq "FIPS 201 Card Conformance Tool v$Version"
                })
            } while ($Windows.Count -eq 0 -and [DateTime]::UtcNow -lt $Deadline)
            if ($Windows.Count -eq 0) {
                Get-Content "$OutputDirectory\native-launch.stderr.log" -ErrorAction SilentlyContinue | Write-Host
                Get-Process -Name CCT -ErrorAction SilentlyContinue |
                    Select-Object Id, Path, MainWindowTitle | Format-List | Out-Host
                throw "CCT.exe did not open its window without system Java."
            }
            Write-Host "CCT.exe startup passed without system Java. Launcher PID $($Process.Id); window PID $($Windows[0].Id)."
        } finally {
            Get-Process -Name CCT -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq "$Expanded\CCT.exe" } |
                ForEach-Object {
                    $_.CloseMainWindow() | Out-Null
                    if (-not $_.WaitForExit(5000)) { $_.Kill(); $_.WaitForExit(5000) | Out-Null }
                }
            $env:PATH = $PreviousPath; $env:JAVA_HOME = $PreviousJava; $env:LOCALAPPDATA = $PreviousData
        }
    }
    Write-Host "Created $Zip"
    Write-Host "SHA-256: $Hash"
} finally {
    $env:JAVA_HOME = $PreviousJavaHome
    Remove-Item -LiteralPath $Work -Recurse -Force
}

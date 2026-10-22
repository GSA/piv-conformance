[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [switch] $SkipBuild,
    [switch] $SmokeTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Jdk = $env:JAVA_HOME
if (-not $Jdk -or -not (Test-Path "$Jdk\bin\jpackage.exe")) {
    throw "Set JAVA_HOME to a Windows Java 17 JDK with jpackage. Clients do not need a JDK."
}
$CompilerVersion = & "$Jdk\bin\javac.exe" -version 2>&1
if ($LASTEXITCODE -ne 0 -or "$CompilerVersion" -notmatch '^javac 17\.') {
    throw "The build requires a Java 17 JDK."
}
if (-not $SkipBuild) { & "$PSScriptRoot\build-application.ps1" }
$Version = (Get-Content "$RepositoryRoot\tools\85b-swing-gui\src\main\resources\build.version" -Raw).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+(-rc\d+)?$') { throw "Invalid version: $Version" }
foreach ($Module in @("cardlib", "conformancelib")) {
    if ((Get-Content "$RepositoryRoot\$Module\src\main\resources\build.version" -Raw).Trim() -ne $Version) {
        throw "$Module version does not match the GUI."
    }
}

# Keep the full JRE so dynamic JUnit, crypto providers and PC/SC retain their modules.
$RuntimeVersion = "17.0.20.1+1"
$RuntimeUrl = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jre_x64_windows_hotspot_17.0.20.1_1.zip"
$RuntimeHash = "bc21a93923103cdaac93ee337b0ae4365e739fde36df823dd456bc67c8a9d352"
$Cache = Join-Path $RepositoryRoot "build\toolchains"
New-Item -ItemType Directory -Path $Cache -Force | Out-Null
$RuntimeArchive = Join-Path $Cache "temurin-$RuntimeVersion-windows-x64-jre.zip"
if (-not (Test-Path -LiteralPath $RuntimeArchive)) {
    Invoke-WebRequest -Uri $RuntimeUrl -OutFile $RuntimeArchive
}
if ((Get-FileHash $RuntimeArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $RuntimeHash) {
    throw "Temurin archive checksum mismatch. Remove $RuntimeArchive and retry."
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
    Expand-Archive -LiteralPath $RuntimeArchive -DestinationPath "$Work\jre"
    $Runtime = @(Get-ChildItem "$Work\jre" -Directory)
    if ($Runtime.Count -ne 1) { throw "Unexpected JRE archive layout." }
    $Runtime = $Runtime[0].FullName
    $Release = Get-Content "$Runtime\release" -Raw
    if ($Release -notmatch '(?m)^JAVA_VERSION="17\.0\.20\.1"\r?$' -or
        $Release -notmatch '(?m)^OS_NAME="Windows"\r?$' -or
        $Release -notmatch '(?m)^OS_ARCH="(x86_64|amd64)"\r?$') {
        throw "Expected Temurin $RuntimeVersion for Windows x64."
    }
    if (-not (Test-Path "$Runtime\legal\java.base\LICENSE")) { throw "Runtime license is missing." }
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
        --description "PIV Card Conformance Tool" --java-options "-Dcct.packaged=true"
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
      "Bundled runtime: Eclipse Temurin $RuntimeVersion", "Runtime archive: $RuntimeUrl",
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
            $Process = Start-Process "$Expanded\CCT.exe" -WorkingDirectory $env:TEMP -PassThru
            $Deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 500
                $Process.Refresh()
            } while (-not $Process.HasExited -and -not $Process.MainWindowTitle -and [DateTime]::UtcNow -lt $Deadline)
            if ($Process.HasExited -or $Process.MainWindowTitle -ne "FIPS 201 Card Conformance Tool") {
                throw "CCT.exe did not open its window without system Java."
            }
            Write-Host "CCT.exe startup passed with Java absent from PATH and an unrelated working directory."
        } finally {
            if ($Process -and -not $Process.HasExited) {
                $Process.CloseMainWindow() | Out-Null
                if (-not $Process.WaitForExit(5000)) { $Process.Kill() }
            }
            $env:PATH = $PreviousPath; $env:JAVA_HOME = $PreviousJava; $env:LOCALAPPDATA = $PreviousData
        }
    }
    Write-Host "Created $Zip"
    Write-Host "SHA-256: $Hash"
} finally {
    Remove-Item -LiteralPath $Work -Recurse -Force
}

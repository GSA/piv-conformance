[CmdletBinding()]
param(
    [string] $OutputDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepositoryRoot "dist"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Executable,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,

        [Parameter(Mandatory = $true)]
        [string] $FailureMessage
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE."
    }
}

function Invoke-GradleBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProjectDirectory,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    $ProjectPath = Join-Path $RepositoryRoot $ProjectDirectory
    Push-Location $ProjectPath
    try {
        Invoke-Checked -Executable (Join-Path $ProjectPath "gradlew.bat") `
            -Arguments $Arguments `
            -FailureMessage "Gradle failed in $ProjectDirectory."
    }
    finally {
        Pop-Location
    }
}

if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
    throw "JAVA_HOME must point to a Windows x64 Java 17 JDK."
}

$JavaHome = (Resolve-Path $env:JAVA_HOME).Path
$JavaExecutable = Join-Path $JavaHome "bin\java.exe"
$JarExecutable = Join-Path $JavaHome "bin\jar.exe"
$JpackageExecutable = Join-Path $JavaHome "bin\jpackage.exe"
@($JavaExecutable, $JarExecutable, $JpackageExecutable) | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
        throw "JAVA_HOME is not a full Windows JDK with $([System.IO.Path]::GetFileName($_)): $JavaHome"
    }
}

$JavaVersion = (& $JavaExecutable -version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $JavaVersion -notmatch 'version "17(?:\.|\")') {
    throw "CCT Windows packaging requires Java 17. Detected:`n$JavaVersion"
}
$JpackageVersion = (& $JpackageExecutable --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $JpackageVersion -notmatch '^17(?:\.|$)') {
    throw "CCT Windows packaging requires the Java 17 jpackage tool. Detected: $JpackageVersion"
}

$JavaReleaseFile = Join-Path $JavaHome "release"
if (-not (Test-Path -LiteralPath $JavaReleaseFile -PathType Leaf)) {
    throw "JAVA_HOME has no release metadata: $JavaReleaseFile"
}
$JavaRelease = Get-Content -LiteralPath $JavaReleaseFile -Raw
if ($JavaRelease -notmatch '(?m)^OS_NAME="Windows"\r?$' -or
    $JavaRelease -notmatch '(?m)^OS_ARCH="(amd64|x86_64)"\r?$') {
    throw "JAVA_HOME must point to a Windows x64 Java 17 JDK."
}

Write-Host "Building CCT with Java 17 and Gradle wrappers..."
Invoke-GradleBuild -ProjectDirectory "cardlib" -Arguments @(
    "--no-daemon", "clean", "build", "install", "installSource"
)
Invoke-GradleBuild -ProjectDirectory "conformancelib" -Arguments @(
    "--no-daemon", "clean", "build", "install", "installSource"
)
Invoke-GradleBuild -ProjectDirectory "tools\85b-swing-gui" -Arguments @(
    "--no-daemon", "clean", "build", "shadowJar"
)

$VersionFile = Join-Path $RepositoryRoot "tools\85b-swing-gui\src\main\resources\build.version"
$Version = (Get-Content -LiteralPath $VersionFile -Raw).Trim()
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') {
    throw "Invalid CCT build.version: $Version"
}

$JpackageAppVersionMatch = [regex]::Match($Version, '^\d+(?:\.\d+){0,3}')
if (-not $JpackageAppVersionMatch.Success) {
    throw "build.version must start with a numeric version accepted by jpackage: $Version"
}
$JpackageAppVersion = $JpackageAppVersionMatch.Value

$ShadowJar = Join-Path $RepositoryRoot "tools\85b-swing-gui\build\libs\gov.gsa.pivconformance.gui-$Version-shadow.jar"
if (-not (Test-Path -LiteralPath $ShadowJar -PathType Leaf)) {
    throw "Missing shaded application JAR: $ShadowJar"
}
$JarEntries = & $JarExecutable tf $ShadowJar
if ($LASTEXITCODE -ne 0 -or
    $JarEntries -notcontains "gov/gsa/pivconformance/gui/GuiRunnerApplication.class") {
    throw "The shaded JAR does not contain the CCT main class."
}

$BuildRoot = Join-Path $RepositoryRoot "build\windows-jpackage"
$InputDirectory = Join-Path $BuildRoot "input"
$ImageOutputDirectory = Join-Path $BuildRoot "image"
if (Test-Path -LiteralPath $BuildRoot) {
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $InputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $ImageOutputDirectory -Force | Out-Null

Copy-Item -LiteralPath $ShadowJar -Destination (Join-Path $InputDirectory "cct.jar")
Copy-Item -LiteralPath $VersionFile -Destination $InputDirectory
Copy-Item -LiteralPath (Join-Path $RepositoryRoot "cardlib\src\main\resources\user_log_config.xml") `
    -Destination $InputDirectory
Copy-Item -LiteralPath (Join-Path $RepositoryRoot "conformancelib\src\main\resources\pdval.properties") `
    -Destination $InputDirectory
Copy-Item -LiteralPath (Join-Path $RepositoryRoot "conformancelib\src\main\resources\x509-certs") `
    -Destination $InputDirectory -Recurse
Copy-Item -LiteralPath (Join-Path $RepositoryRoot "LICENSE.md") -Destination $InputDirectory

$DatabaseNames = @(
    "PIV_Production_Cards.db",
    "PIV-I_Production_Cards.db",
    "PIV_ICAM_Test_Cards.db",
    "PIV-I_ICAM_Test_Cards.db"
)
foreach ($DatabaseName in $DatabaseNames) {
    $SourceDatabase = Join-Path $RepositoryRoot "conformancelib\testdata\$DatabaseName"
    $StagedDatabase = Join-Path $InputDirectory $DatabaseName
    if (-not (Test-Path -LiteralPath $SourceDatabase -PathType Leaf)) {
        throw "Missing required CCT database: $SourceDatabase"
    }
    Copy-Item -LiteralPath $SourceDatabase -Destination $StagedDatabase
    $SourceHash = (Get-FileHash -LiteralPath $SourceDatabase -Algorithm SHA256).Hash
    $StagedHash = (Get-FileHash -LiteralPath $StagedDatabase -Algorithm SHA256).Hash
    if ($SourceHash -ne $StagedHash) {
        throw "Staged database differs from the protected source database: $DatabaseName"
    }
}

$JpackageArguments = @(
    "--type", "app-image",
    "--name", "CCT",
    "--dest", $ImageOutputDirectory,
    "--input", $InputDirectory,
    "--main-jar", "cct.jar",
    "--main-class", "gov.gsa.pivconformance.gui.GuiRunnerApplication",
    "--app-version", $JpackageAppVersion,
    "--vendor", "U.S. General Services Administration",
    "--description", "FIPS 201 Card Conformance Tool",
    "--java-options", "-Dcct.packaged=true",
    "--add-modules", "java.smartcardio,jdk.crypto.ec,jdk.crypto.cryptoki",
    "--jlink-options", "--strip-native-commands --strip-debug --no-man-pages --no-header-files --bind-services"
)

Write-Host "Creating the self-contained Windows app image..."
Invoke-Checked -Executable $JpackageExecutable -Arguments $JpackageArguments `
    -FailureMessage "jpackage failed."

$GeneratedImage = Join-Path $ImageOutputDirectory "CCT"
$PackageName = "fips201-card-conformance-tool-$Version-windows-x64"
$PackageDirectory = Join-Path $OutputDirectory $PackageName
$ZipPath = Join-Path $OutputDirectory "$PackageName.zip"
$ChecksumPath = "$ZipPath.sha256"

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if (Test-Path -LiteralPath $PackageDirectory) {
    Remove-Item -LiteralPath $PackageDirectory -Recurse -Force
}
if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
if (Test-Path -LiteralPath $ChecksumPath) {
    Remove-Item -LiteralPath $ChecksumPath -Force
}
Move-Item -LiteralPath $GeneratedImage -Destination $PackageDirectory

$StartHereTemplate = Get-Content -LiteralPath (Join-Path $PSScriptRoot "windows\START_HERE.txt") -Raw
$StartHere = $StartHereTemplate.Replace("{{VERSION}}", $Version)
[System.IO.File]::WriteAllText(
    (Join-Path $PackageDirectory "START_HERE.txt"),
    $StartHere,
    [System.Text.UTF8Encoding]::new($false)
)

$Commit = "unavailable (source archive or Git not installed)"
try {
    $CommitValue = (& git -C $RepositoryRoot rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($CommitValue)) {
        $Commit = $CommitValue.Trim()
    }
}
catch {
    # Git metadata is useful but is not required to build from a source archive.
}
$BuildInformation = @(
    "FIPS 201 Card Conformance Tool"
    "Version: $Version"
    "jpackage app version: $JpackageAppVersion"
    "Platform: Windows x64"
    "Java: $($JavaVersion.Trim())"
    "Built (UTC): $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    "Source commit: $Commit"
) -join "`r`n"
[System.IO.File]::WriteAllText(
    (Join-Path $PackageDirectory "BUILD-INFO.txt"),
    "$BuildInformation`r`n",
    [System.Text.UTF8Encoding]::new($false)
)

$RequiredFiles = @(
    "CCT.exe",
    "app\CCT.cfg",
    "app\cct.jar",
    "app\user_log_config.xml",
    "app\pdval.properties",
    "app\x509-certs\cacerts.jks",
    "runtime\bin\server\jvm.dll"
) + ($DatabaseNames | ForEach-Object { "app\$_" })
foreach ($RelativePath in $RequiredFiles) {
    $RequiredPath = Join-Path $PackageDirectory $RelativePath
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Windows app image is missing $RelativePath."
    }
}

Compress-Archive -LiteralPath $PackageDirectory -DestinationPath $ZipPath -CompressionLevel Optimal
$ZipHash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText(
    $ChecksumPath,
    "$ZipHash  $([System.IO.Path]::GetFileName($ZipPath))`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host ""
Write-Host "Windows distribution created successfully:"
Write-Host "  $ZipPath"
Write-Host "  $ChecksumPath"
Write-Host "SHA-256: $ZipHash"

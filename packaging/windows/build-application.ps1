[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Invoke-GradleBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProjectDirectory,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    Push-Location (Join-Path $RepositoryRoot $ProjectDirectory)
    try {
        & ".\gradlew.bat" @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Gradle failed in $ProjectDirectory with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

Invoke-GradleBuild -ProjectDirectory "cardlib" -Arguments @(
    "--no-daemon", "clean", "check", "install"
)
Invoke-GradleBuild -ProjectDirectory "conformancelib" -Arguments @(
    "--no-daemon", "clean", "check", "install"
)
Invoke-GradleBuild -ProjectDirectory "tools\85b-swing-gui" -Arguments @(
    "--no-daemon", "clean", "test", "shadowJar"
)

param(
    [Parameter(Mandatory=$false)]
    [string]$ProjectsDirectory,
    [Parameter(Mandatory=$false)]
    [string]$SingleProject,
    [string]$ReportDirectory = "./reports",
    [string]$PythonPath = "",
    [switch]$Help
)

if ($Help) {
    Write-Host "MuleSoft Project Scanner - PowerShell Script"
    Write-Host ""
    Write-Host "USAGE:"
    Write-Host "  .\scan_all_projects.ps1 -ProjectsDirectory <path> [-ReportDirectory <path>] [-PythonPath <path>]"
    Write-Host "  .\scan_all_projects.ps1 -SingleProject <path> [-ReportDirectory <path>] [-PythonPath <path>]"
    Write-Host ""
    Write-Host "PARAMETERS:"
    Write-Host "  -ProjectsDirectory    Base directory containing MuleSoft project repositories (for batch scanning)"
    Write-Host "  -SingleProject        Path to a single MuleSoft project to scan"
    Write-Host "  -ReportDirectory      Directory to store HTML reports (default: ./reports)"
    Write-Host "  -PythonPath          Path to Python executable (auto-detected if not specified)"
    Write-Host "  -Help                Show this help message"
    Write-Host ""
    Write-Host "EXAMPLES:"
    Write-Host "  # Scan all projects in a directory"
    Write-Host "  .\scan_all_projects.ps1 -ProjectsDirectory 'C:\Projects\MuleSoft'"
    Write-Host "  .\scan_all_projects.ps1 -ProjectsDirectory 'C:\Projects\MuleSoft' -ReportDirectory 'C:\Reports'"
    Write-Host ""
    Write-Host "  # Scan a single project"
    Write-Host "  .\scan_all_projects.ps1 -SingleProject 'C:\Projects\MuleSoft\my-project'"
    Write-Host "  .\scan_all_projects.ps1 -SingleProject 'C:\Projects\MuleSoft\my-project' -ReportDirectory 'C:\Reports'"
    exit 0
}

function Find-PythonExecutable {
    $pythonCommands = @("python", "python3", "py")
    
    foreach ($cmd in $pythonCommands) {
        try {
            $null = & $cmd --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Found Python: $cmd"
                return $cmd
            }
        }
        catch {
            continue
        }
    }
    
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe",
        "$env:PROGRAMFILES\Python*\python.exe"
    )
    
    foreach ($pathPattern in $commonPaths) {
        $paths = Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue
        if ($paths) {
            $pythonExe = $paths[0].FullName
            try {
                $null = & $pythonExe --version 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Found Python: $pythonExe"
                    return $pythonExe
                }
            }
            catch {
                continue
            }
        }
    }
    
    return $null
}

# Validate that at least one scanning mode is specified
if ([string]::IsNullOrEmpty($ProjectsDirectory) -and [string]::IsNullOrEmpty($SingleProject)) {
    Write-Error "Either -ProjectsDirectory or -SingleProject must be specified. Use -Help for usage information."
    exit 1
}

# Validate that only one scanning mode is specified
if (![string]::IsNullOrEmpty($ProjectsDirectory) -and ![string]::IsNullOrEmpty($SingleProject)) {
    Write-Error "Cannot specify both -ProjectsDirectory and -SingleProject. Use only one scanning mode."
    exit 1
}

# Find Python
if ([string]::IsNullOrEmpty($PythonPath)) {
    $PythonPath = Find-PythonExecutable
    if ($null -eq $PythonPath) {
        Write-Error "Python executable not found. Please install Python or specify path with -PythonPath"
        exit 1
    }
} else {
    if (!(Test-Path $PythonPath)) {
        Write-Error "Python executable not found at: $PythonPath"
        exit 1
    }
}

# Create report directory
if (!(Test-Path $ReportDirectory)) { 
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null 
    Write-Host "Created report directory: $ReportDirectory"
}

$ProjectsDirectory = Resolve-Path $ProjectsDirectory
$ReportDirectory = Resolve-Path $ReportDirectory

Write-Host "Starting MuleSoft project scan..."
if (![string]::IsNullOrEmpty($ProjectsDirectory)) {
    Write-Host "Scan Mode: Batch scanning all projects"
    Write-Host "Projects Directory: $ProjectsDirectory"
} else {
    Write-Host "Scan Mode: Single project scanning"
    Write-Host "Project Path: $SingleProject"
}
Write-Host "Report Directory: $ReportDirectory"
Write-Host "Python Executable: $PythonPath"
Write-Host ""

$successCount = 0
$failureCount = 0

# Function to process a single project
function Process-SingleProject {
    param(
        [string]$ProjectPath,
        [string]$ReportDir,
        [string]$PythonExe
    )
    
    $projectName = Split-Path $ProjectPath -Leaf
    $reportFile = "$projectName-mule_report.html"
    $reportPath = Join-Path $ReportDir $reportFile

    Write-Host "Processing: $projectName" -ForegroundColor Cyan
    
    try {
        & $PythonExe -m "mule_validator.main" "$ProjectPath" --report-file "$reportPath"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Success: Report generated at $reportPath" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Failed: Validation failed for $projectName"
            return $false
        }
    }
    catch {
        Write-Error "Error processing $projectName : $_"
        return $false
    }
}

# Main processing logic
if (![string]::IsNullOrEmpty($ProjectsDirectory)) {
    # Batch scanning mode
    Get-ChildItem -Path $ProjectsDirectory -Directory | ForEach-Object {
        $repoName = $_.Name
        $repoPath = $_.FullName
        $reportFile = "$repoName-mule_report.html"
        $reportPath = Join-Path $ReportDirectory $reportFile

        Write-Host "Processing: $repoName" -ForegroundColor Cyan
        
        try {
            & $PythonPath -m "mule_validator.main" "$repoPath" --report-file "$reportPath"
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Success: Report generated at $reportPath" -ForegroundColor Green
                $script:successCount++
            } else {
                Write-Warning "Failed: Validation failed for $repoName"
                $script:failureCount++
            }
        }
        catch {
            Write-Error "Error processing $repoName : $_"
            $script:failureCount++
        }
        
        Write-Host ""
    }
} else {
    # Single project scanning mode
    $result = Process-SingleProject -ProjectPath $SingleProject -ReportDir $ReportDirectory -PythonExe $PythonPath
    if ($result) {
        $successCount = 1
        $failureCount = 0
    } else {
        $successCount = 0
        $failureCount = 1
    }
    Write-Host ""
}

Write-Host "Scan completed!" -ForegroundColor Yellow
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failureCount" -ForegroundColor Red
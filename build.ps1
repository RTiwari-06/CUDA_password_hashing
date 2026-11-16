# build.ps1 - Automated build script for the CUDA Password Hashing Demonstration (Windows)
# Compiles:
#   build/test_crypto.exe   (NIST test-vector verification suite)
#   build/cuda_cracker.exe  (CPU + CUDA brute-force / dictionary cracker & benchmark CLI)
# Flags (per AGENTS.md):
#   nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# ---------------------------------------------------------------- directories
foreach ($d in @("include", "src", "data", "scripts", "results", "build")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null
}

# ---------------------------------------------------------------- locate nvcc
if (-not (Get-Command nvcc -ErrorAction SilentlyContinue)) {
    $cudaRoot = Get-ChildItem "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA" -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -First 1
    if ($cudaRoot) {
        $env:PATH = (Join-Path $cudaRoot.FullName "bin") + ";" + $env:PATH
        Write-Host "[build] Added CUDA toolkit to PATH: $($cudaRoot.FullName)"
    }
}
if (-not (Get-Command nvcc -ErrorAction SilentlyContinue)) {
    throw "[build] FATAL: nvcc.exe not found. Install the NVIDIA CUDA Toolkit."
}

# ------------------------------------------------- load MSVC env if cl absent
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vcvarsCandidates = @(
        "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    )
    $vcvars = $candidates = $vcvarsCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $vcvars) { throw "[build] FATAL: vcvars64.bat not found. Install MSVC Build Tools." }
    Write-Host "[build] Loading MSVC environment: $vcvars"
    cmd /c "`"$vcvars`" && set" | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
    }
}
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw "[build] FATAL: cl.exe still not in PATH after loading vcvars64.bat."
}
Write-Host "[build] cl.exe : $((Get-Command cl.exe).Source)"
Write-Host "[build] nvcc   : $((Get-Command nvcc).Source)"

# ------------------------------------------------------------------- flags
$common = @("-std=c++17", "-O3", "-arch=sm_86", "-Xcompiler", "/openmp /EHsc", "-allow-unsupported-compiler", "-Iinclude")

Push-Location $root
try {
    Write-Host "`n[build] Compiling src/test_crypto.cu  ->  build/test_crypto.exe"
    & nvcc @common -c src/test_crypto.cu -o build/test_crypto.obj
    if ($LASTEXITCODE -ne 0) { throw "[build] test_crypto compilation failed" }
    & nvcc build/test_crypto.obj -o build/test_crypto.exe
    if ($LASTEXITCODE -ne 0) { throw "[build] test_crypto link failed" }

    Write-Host "`n[build] Compiling CUDA cracker (main + gpu + cpu/omp)  ->  build/cuda_cracker.exe"
    & nvcc @common -c src/cpu_cracker.cpp -o build/cpu_cracker.obj
    if ($LASTEXITCODE -ne 0) { throw "[build] cpu_cracker compilation failed" }
    & nvcc @common -c src/gpu_cracker.cu -o build/gpu_cracker.obj
    if ($LASTEXITCODE -ne 0) { throw "[build] gpu_cracker compilation failed" }
    & nvcc @common -c src/main.cu -o build/main.obj
    if ($LASTEXITCODE -ne 0) { throw "[build] main compilation failed" }
    & nvcc build/main.obj build/gpu_cracker.obj build/cpu_cracker.obj -o build/cuda_cracker.exe
    if ($LASTEXITCODE -ne 0) { throw "[build] cuda_cracker link failed" }

    Write-Host "`n[build] SUCCESS - binaries in build\"
    Get-ChildItem build\*.exe | Format-Table Name, Length -AutoSize
} finally {
    Pop-Location
}

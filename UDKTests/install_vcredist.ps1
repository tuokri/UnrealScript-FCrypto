$ErrorView = 'NormalView'

New-Item "C:\Temp\" -ItemType Directory -ErrorAction SilentlyContinue

Install-Module -Name VcRedist -Force
New-Item -Path C:\Temp\VcRedist -ItemType Directory -Force
$VcList = Get-VcList -Export Unsupported | Where-Object { $_.Release -eq "2012" }
Save-VcRedist -VcList $VcList -Path C:\Temp\VcRedist
Install-VcRedist -Path C:\Temp\VcRedist -VcList $VcList -Silent

Exit $LASTEXITCODE

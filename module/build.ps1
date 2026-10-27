# build.ps1 - CellularPro Unlocker (libxposed API 102, static scope)
$ErrorActionPreference = "Stop"
$L   = "C:\work\cellularpro\lsp2"
$BT  = "C:\AndroidSDK\build-tools\34.0.0"
$AJ  = "C:\AndroidSDK\platforms\android-34\android.jar"
$API = "$L\lib\classes.jar"
$JDK = "D:\JDK-17\bin"
$SRC = "$L\src\io\github\ldxm666\cellularpro\Main.java"

foreach ($d in @("$L\bin\mod","$L\bin\dex","$L\bin\res")) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
Get-ChildItem "$L\bin\mod","$L\bin\dex","$L\bin\res" -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "[1/6] javac"
& "$JDK\javac.exe" -encoding UTF-8 -source 8 -target 8 -nowarn -cp "$AJ;$API" -d "$L\bin\mod" $SRC
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

Write-Host "[2/6] d8"
$cls = (Get-ChildItem "$L\bin\mod" -Recurse -Filter *.class).FullName
& "$BT\d8.bat" --release --min-api 28 --lib $AJ --classpath $API --output "$L\bin\dex" $cls
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

Write-Host "[3/6] aapt2 compile"
& "$BT\aapt2.exe" compile --dir "$L\res" -o "$L\bin\res\res.zip"
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }

Write-Host "[4/6] aapt2 link"
Remove-Item "$L\bin\base.apk" -Force -ErrorAction SilentlyContinue
& "$BT\aapt2.exe" link -o "$L\bin\base.apk" --manifest "$L\AndroidManifest.xml" -I $AJ -A "$L\assets" -R "$L\bin\res\res.zip" --min-sdk-version 28 --target-sdk-version 34 --auto-add-overlay
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

Write-Host "[5/6] pack dex + META-INF"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open("$L\bin\base.apk", 'Update')
$e = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, "$L\bin\dex\classes.dex", "classes.dex", [System.IO.Compression.CompressionLevel]::Optimal)
$e.LastWriteTime = [DateTimeOffset]::new(2020,1,1,0,0,0,[TimeSpan]::Zero)
foreach ($f in (Get-ChildItem "$L\meta" -Recurse -File)) {
    $name = "META-INF/xposed/" + $f.Name
    $old = $zip.GetEntry($name); if ($old) { $old.Delete() }
    $n = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $name, [System.IO.Compression.CompressionLevel]::Optimal)
    $n.LastWriteTime = [DateTimeOffset]::new(2020,1,1,0,0,0,[TimeSpan]::Zero)
}
$zip.Dispose()

Write-Host "[6/6] align + sign"
& "$BT\zipalign.exe" -p -f 4 "$L\bin\base.apk" "$L\bin\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }
Remove-Item "$L\CellularPro-Unlocker.apk" -Force -ErrorAction SilentlyContinue
& "$BT\apksigner.bat" sign --ks C:\work\cellularpro\ks.jks --ks-pass pass:android --key-pass pass:android --ks-key-alias cp --out "$L\CellularPro-Unlocker.apk" "$L\bin\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "sign failed" }
Write-Host ("BUILD_OK " + (Get-Item "$L\CellularPro-Unlocker.apk").Length + " bytes")
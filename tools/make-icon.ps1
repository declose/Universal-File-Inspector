# Generates assets\app.ico (PNG-compressed multi-size icon) with System.Drawing.
# Usage:  powershell -ExecutionPolicy Bypass -File tools\make-icon.ps1
Add-Type -AssemblyName System.Drawing
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "assets\app.ico"
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null

function New-IconPng([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
    $g.Clear([System.Drawing.Color]::Transparent)
    $r = [single]($s * 0.18); $d = $r * 2; $m = [single]($s * 0.04); $w = [single]($s - 2 * $m)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($m, $m, $d, $d, 180, 90); $path.AddArc($m + $w - $d, $m, $d, $d, 270, 90)
    $path.AddArc($m + $w - $d, $m + $w - $d, $d, $d, 0, 90); $path.AddArc($m, $m + $w - $d, $d, $d, 90, 90); $path.CloseFigure()
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush ([System.Drawing.PointF]::new(0, 0)), ([System.Drawing.PointF]::new(0, $s)), ([System.Drawing.Color]::FromArgb(255, 22, 28, 38)), ([System.Drawing.Color]::FromArgb(255, 8, 10, 14))
    $g.FillPath($bg, $path)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 89, 194, 255)), ([single][Math]::Max(1, $s * 0.035))
    $g.DrawPath($pen, $path)
    # title bar dots
    if ($s -ge 32) {
        foreach ($i in 0..2) {
            $c = @([System.Drawing.Color]::FromArgb(255, 240, 113, 120), [System.Drawing.Color]::FromArgb(255, 255, 180, 84), [System.Drawing.Color]::FromArgb(255, 170, 217, 76))[$i]
            $dd = [single]($s * 0.07)
            $g.FillEllipse((New-Object System.Drawing.SolidBrush $c), [single]($s * 0.14 + $i * $s * 0.1), [single]($s * 0.13), $dd, $dd)
        }
    }
    # hex rows
    $green = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 149, 230, 203))
    $dim = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 70, 85, 100))
    $rows = 3; $top = [single]($s * 0.30)
    for ($y = 0; $y -lt $rows; $y++) {
        for ($x = 0; $x -lt 4; $x++) {
            $b = if (($x + $y) % 3 -eq 0) { $dim } else { $green }
            $g.FillRectangle($b, [single]($s * 0.14 + $x * $s * 0.1), [single]($top + $y * $s * 0.12), [single]($s * 0.07), [single]($s * 0.06))
        }
    }
    # magnifier
    $lens = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 255, 180, 84)), ([single][Math]::Max(1.5, $s * 0.07))
    $lx = [single]($s * 0.50); $ly = [single]($s * 0.42); $ld = [single]($s * 0.32)
    $g.FillEllipse((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(90, 89, 194, 255))), $lx, $ly, $ld, $ld)
    $g.DrawEllipse($lens, $lx, $ly, $ld, $ld)
    $lens.StartCap = 'Round'; $lens.EndCap = 'Round'
    $lens.Width = [single][Math]::Max(2, $s * 0.09)
    $g.DrawLine($lens, [single]($lx + $ld * 0.85), [single]($ly + $ld * 0.85), [single]($s * 0.90), [single]($s * 0.90))
    # prompt
    if ($s -ge 24) {
        $font = New-Object System.Drawing.Font 'Consolas', ([single]($s * 0.16)), ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
        $g.DrawString('>_', $font, (New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 170, 217, 76))), [single]($s * 0.12), [single]($s * 0.70))
    }
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$pngs = @(); foreach ($s in $sizes) { $pngs += , (New-IconPng $s) }
$fs = [System.IO.File]::Create($out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $len = $pngs[$i].Length
    $bw.Write([byte]($s % 256)); $bw.Write([byte]($s % 256)); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$len); $bw.Write([uint32]$offset)
    $offset += $len
}
foreach ($p in $pngs) { $bw.Write($p) }
$bw.Close()
Write-Host "Wrote $out"

<#
.SYNOPSIS
    Audyt wycieków poświadczeń firmowych przez Have I Been Pwned API 
.DESCRIPTION
    Skrypt pobiera klucz API z pliku api_key.txt lub parametru, czyta e=mail z emails.txt,
    sprawdza je w Have i been pwned API i generuje raport w pliku CSV oraz w konsoli.
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$ApiKey,

    [Parameter(Mandatory=$false)]
    [string]$KeyFile = "api_key.txt",

    [Parameter(Mandatory=$false)]
    [string]$InputFile = "emails.txt",

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "Raport_Wyciekow.csv"
)

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    if (Test-Path $KeyFile) {
        $ApiKey = (Get-Content$KeyFile -Raw).Trim()
    } else {
        Write-Host "[!] BŁĄD: Brak klucza API!" -ForegroundColor Red
        Write-Host "Utwórz plik '$KeyFile' w folderze ze skryptem i wklej w nim swój klucz HIBP," -ForegroundColor Yellow
        Write-Host "albo uruchom skrypt z parametrem: .\Audit-HIBPBreaches.ps1 -ApiKey 'TWÓJ_KLUCZ'" -ForegroundColor Yellow
        return
    }
}

if (-not (Test-Path $InputFile)) {
    Write-Host "[!] Brak pliku $InputFile. Tworzę przykładowy plik..." -ForegroundColor Yellow
    @"
jan.kowalski@twojafirma.pl
anna.nowak@twojafirma.pl
puchatek@twojafirma.pl
"@ | Out-File -FilePath $InputFile -Encoding utf8
    Write-Host "[+] Utworzono $InputFile. Uzupełnij go właściwymi mailami i uruchom skrypt ponownie." -ForegroundColor Green
    return
}

$emails = Get-Content $InputFile \vert{} Where-Object {$_ -match "\S" }
$results = @()

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " Rozpoczynam audyt HIBP dla $($emails.Count) adresów e-mail " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$headers = @{
    "hibp-api-key" = $ApiKey
    "user-agent"   = "PowerShell-HIBP-Audit-Script"
}

$count = 0
foreach ($email in $emails) {$count++
    $emailClean =$email.Trim()
    Write-Host "[$count/$($emails.Count)] Sprawdzam:$emailClean ... " -NoNewline

    $url = "https://haveibeenpwned.com/api/v3/breachedaccount/$([Uri]::EscapeDataString($emailClean))?truncateResponse=false"

    try {
        $response = Invoke-RestMethod -Uri $url -Headers$headers -Method Get -ErrorAction Stop
        
        # Status 200 -Jest Afera znaleziono przeciek :(
        $breachNames = ($response | Select-Object -ExpandProperty Name) -join ", "
        $dataTypes   = ($response | Select-Object -ExpandProperty DataClasses | Select-Object -Unique) -join ", "
        
        Write-Host "ZNALAZŁEM WYCIEKI ($($response.Count))!" -ForegroundColor Red
        
        $results += [PSCustomObject]@{
            Email            = $emailClean
            CzyWyciekl       = "TAK"
            LiczbaWyciekow   = $response.Count
            NazwyWyciekow    = $breachNames
            WycieknieteDane  = $dataTypes
        }
    }
    catch {
        $statusCode =$_.Exception.Response.StatusCode.Value__
        
        if ($statusCode -eq 404) {
            # Status 404 - Czysciutko B)
            Write-Host "Czysto" -ForegroundColor Green
            $results += [PSCustomObject]@{
                Email            = $emailClean
                CzyWyciekl       = "NIE"
                LiczbaWyciekow   = 0
                NazwyWyciekow    = "Brak"
                WycieknieteDane  = "Brak"
            }
        }
        elseif ($statusCode -eq 429) {
            Write-Host "Przekroczono limit zapytań! Czekam 3 sekundy..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
        }
        else {
            Write-Host "Błąd HTTP: $statusCode" -ForegroundColor DarkRed
        }
    }

    # PRZRWA BO NIE MOZNA WYSYŁAĆ CIĄGIEM
    Start-Sleep -Milliseconds 1600
}


$results \vert{} Export-Csv -Path$OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "[+] Audyt zakończony! Wyniki zapisano do: $OutputFile" -ForegroundColor Green

$threats = $results | Where-Object { $_.CzyWyciekl -eq "TAK" }
Write-Host "`nPODSUMOWANIE DLA KIEROWNIKA:" -ForegroundColor Yellow
Write-Host " - Przebadano adresów: $($emails.Count)"
Write-Host " - Adresy w bazach wyciekowych: $($threats.Count)" -ForegroundColor ($threats.Count -gt 0 ? "Red" : "Green")
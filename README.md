# HIBP Domain Breach Auditor (PowerShell)

Skrypt PowerShell służący do automatycznej weryfikacji firmowych adresów e-mail pod kątem wycieków poświadczeń w bazie **Have I Been Pwned API v3**.

## Wymagania
* PowerShell 5.1 / 7+
* Klucz API do serwisu Have I Been Pwned (HIBP)

## Szybki start
1. Sklonuj repozytorium: `git clone https://github.com/TwojNick/hibp-auditor.git`
2. Utwórz plik `api_key.txt` w głównym katalogu i wklej swój klucz HIBP API.
3. Utwórz plik `emails.txt` i wklej adresy e-mail (jeden pod drugim).
4. Uruchom skrypt:
   ```powershell
   .\Audit-HIBPBreaches.ps1
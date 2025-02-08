# Enkriptovani Fajl Sistem (EFS)

## Opis Projekta
Ovaj projekat implementira jednostavan sistem za dijeljeni enkriptovani fajl sistem (EFS) za više korisnika. Sistem omogućava:
- Registraciju i prijavu korisnika pomoću korisničkog imena, lozinke i digitalnog sertifikata.
- Upravljanje fajlovima i direktorijumima unutar korisničkog prostora.
- Enkripciju i dekripciju fajlova koristeći različite algoritme.
- Dijeljenje fajlova između korisnika putem `Shared` direktorijuma.
- Validaciju digitalnih sertifikata i provjeru potpisa.

## Tehnologije
- **C#** (.NET)
- **RSA 2048** (za validaciju sertifikata)
- **AES, TripleDES, Blowfish** (za enkripciju fajlova)
- **X.509 Sertifikati** (za autentifikaciju korisnika)
- **BouncyCastle** (za kriptografske operacije)

## Instalacija i Pokretanje
### 1. Kloniranje repozitorija
```sh
 git clone https://github.com/tvoj-repozitorij/EFS.git
 cd EFS
```

### 2. Pokretanje aplikacije
Otvoriti projekat u Visual Studio i pokrenuti `Program.cs`.

## Korištenje
### 1. Registracija korisnika
Korisnik unosi:
- Korisničko ime
- Lozinku
- Putanju do svog digitalnog sertifikata

Ako je sertifikat validan, korisnik se uspješno registruje.

### 2. Prijava korisnika
Korisnik unosi:
- Korisničko ime
- Lozinku

Nakon uspješne prijave, vrši se provjera validnosti sertifikata.

### 3. Operacije nad fajlovima
**Dostupne opcije nakon prijave:**
1. Dodavanje fajla
2. Preuzimanje fajla
3. Dijeljenje fajla sa drugim korisnikom
4. Pregled direktorijuma
5. Brisanje fajla
6. Kreiranje direktorijuma
7. Brisanje direktorijuma
8. Odjava

## Struktura Projekta
```
EFS/
│── Program.cs                 # Glavni program
│── Managers/
│   ├── CertificateManager.cs  # Upravljanje sertifikatima
│   ├── UserManager.cs         # Upravljanje korisnicima
│   ├── FileSystemManager.cs   # Upravljanje fajlovima
│── Utilities/
│   ├── EncryptionUtility.cs   # Kriptografske operacije
│── Users/                     # Folder sa korisničkim direktorijumima
│── Shared/                    # Folder za dijeljene fajlove
│── Sertifikati/                # CA sertifikati i CRL liste
```

## Sigurnosne Mjere
- Lozinke se ne čuvaju u običnom tekstu.
- Korisnici moraju imati validan digitalni sertifikat za pristup sistemu.
- Fajlovi su enkriptovani prije spremanja na disk.
- Dijeljeni fajlovi koriste odvojene enkripcijske ključeve.

## Planirana Poboljšanja
- Bolja podrška za upravljanje ključevima
- Bolja provjera validnosti sertifikata
- Poboljšana sigurnost pri dijeljenju fajlova

## Autor
Mladen Grbić | [GitHub profil](https://github.com/MladenGrbic)


using System;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KriptografijaProjekat.Managers;
using KriptografijaProjekat.Managers.KriptografijaProjekat.Managers;
using KriptografijaProjekat.Models;
using KriptografijaProjekat.Utilities;
using Org.BouncyCastle.Asn1.IsisMtt.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace KriptografijaProjekat
{
    class Program
    {
        static void Main(string[] args)
        {
            // Inicijalizacija osnovnih komponenti
            string baseDirectory = "Users";
            string keyString = "sigurnost";
            byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(keyString));
            string ivString = "1234567890";
            byte[] iv = SHA256.HashData(Encoding.UTF8.GetBytes(ivString));
            Directory.CreateDirectory(baseDirectory);
            int encChoice = 0;

            // Putanje do CA sertifikata i CRL liste
            string caCertificatePath = "Sertifikati/rootca.pem";
            string crlPath = "Sertifikati/crl/crl.pem";

            // Provjera postojanja sertifikata i CRL liste
            if (!File.Exists(caCertificatePath))
            {
                Console.WriteLine("CA sertifikat nije pronađen na lokaciji: " + caCertificatePath);
                return;
            }

            if (!File.Exists(crlPath))
            {
                Console.WriteLine("CRL lista nije pronađena na lokaciji: " + crlPath);
                return;
            }

            // Inicijalizacija CertificateManager-a
            var certificateManager = new CertificateManager(caCertificatePath, crlPath);
            Console.WriteLine("CA sertifikat i CRL lista uspješno učitani.");

            // Inicijalizacija FileSystemManager-a
            var fileSystemManager = new FileSystemManager(baseDirectory);

            // Inicijalizacija UserManager-a
            var userManager = new UserManager(fileSystemManager);

            Console.WriteLine("Aplikacija je uspješno inicijalizovana.");

            Console.WriteLine("Dobrodošli u sistem! Odaberite opciju:");
            Console.WriteLine("1. Registracija" +
                "\n2. Prijava");
            int izbor = int.Parse(Console.ReadLine());

            if (izbor == 1)
            {
                // Registracija korisnika
                Console.Write("Unesite korisničko ime: ");
                string username = Console.ReadLine();

                Console.Write("Unesite lozinku: ");
                string password = Console.ReadLine();

                Console.Write("Unesite putanju do vašeg sertifikata: ");
                string certificatePath = Console.ReadLine();

                if (!certificateManager.ValidateCertificate(certificatePath))
                {
                    Console.WriteLine("Vaš sertifikat nije validan! Registracija nije moguća.");
                    return;
                }

                if (userManager.RegisterUser(username, password, certificatePath))
                {
                    Console.WriteLine("Registracija uspješna! Možete se prijaviti.");
                }
                else
                {
                    Console.WriteLine("Greška: Korisnik sa tim imenom već postoji.");
                }
            }
            else if (izbor == 2)
            {
                // Prijava korisnika
                Console.Write("Unesite korisničko ime: ");
                string username = Console.ReadLine();

                Console.Write("Unesite lozinku: ");
                string password = Console.ReadLine();

                var user = userManager.Login(username, password);
                if (user == null)
                {
                    Console.WriteLine("Prijava nije uspješna.");
                    return;
                }

                var userCertificate = certificateManager.GetCertificateFromFile(user.CertificatePath);

                Console.WriteLine("Validacija sertifikata...");
                if (certificateManager.ValidateSignature(userCertificate))
                {
                    Console.WriteLine("Korisnički sertifikata NIJE validan.");
                    return;
                }
                else {
                    Console.WriteLine("Korisnički sertifikata je validan.");
                }

                Console.WriteLine($"Dobrodošli, {user.Username}!");

                FileSystemManager.PrintDirectoryTree("Users/"+user.Username, "",true);
                string currentDirectory = Directory.GetCurrentDirectory();

                FileSystemManager.PrintDirectoryTreeFiltered(currentDirectory+"/Shared", "", true, user.Username);
                X509Certificate2 cert = new X509Certificate2(user.CertificatePath, "sigurnost");


                Console.WriteLine("Dostupne opcije:");
                Console.WriteLine("1. Dodaj fajl\n" +
                    "2. Preuzmi fajl\n" +
                    "3. Dijeli fajl\n" +
                    "4. Prikaz datoteka i direktorijuma sistema\n" +
                    "5. Obriši fajl\n" +
                    "6. Kreiraj direktoriju\n" +
                    "7. Obriši direktorijum\n" +
                    "8. Odjava");
                bool pom=true;
                
                while (pom)
                {
                    Console.Write("Unesite opciju: ");
                    int opcija = int.Parse(Console.ReadLine());
                    encChoice = 0;
                    switch (opcija)
                    {
                        // Dodavanje fajla
                        case 1:
                            Console.Write("Unesite gdje se fajl nalazi na vašem sistemu: ");
                            string sourcePath = Console.ReadLine();

                            Console.Write("Unesite gdje želite da smjestite fajl u EFSu: ");
                            string destinationName = Console.ReadLine();

                            Console.WriteLine("Odaberite algoritam za enkripciju, ako je fajl iz Shared foldera, koristite opciju 1: " +
                                "\n1. AES " +
                                "\n2. TripleDES " +
                                "\n3. Blowfish ");
                            encChoice = int.Parse(Console.ReadLine());

                            FileSystemManager.SignFileAndAppend(sourcePath, cert);

                            if (encChoice == 1)
                            {
                                EncryptionUtility.EncryptFileAES(sourcePath, Path.Combine(currentDirectory, "Users", user.Username, destinationName), key, iv);
                            }
                            else if (encChoice == 2)
                            {
                                EncryptionUtility.EncryptWithTripleDES(sourcePath, Path.Combine(currentDirectory, "Users", user.Username, destinationName), key, iv);
                            }
                            else if (encChoice == 3)
                            {
                                EncryptionUtility.EncryptWithBlowfish(sourcePath, Path.Combine(currentDirectory, "Users", user.Username, destinationName), key, iv);
                            }
                            else
                            {
                                Console.WriteLine("Pogrešan izbor.");
                            }
                            Console.WriteLine("Fajl uspješno dodan.");
                            break;

                        // Preuzimanje fajla
                        case 2:
                            Console.Write("Unesite naziv fajla za preuzimanje: ");
                            string downloadFileName = Console.ReadLine();

                            Console.Write("Unesite putanju za preuzimanje: ");
                            string downloadDestination = Console.ReadLine();

                            Console.WriteLine("Odaberite algoritam kojim je fajl enkriptovan: " +
                                "\n1. AES " +
                                "\n2. TripleDES " +
                                "\n3. Blowfish ");
                            encChoice = int.Parse(Console.ReadLine());
                           
                            if (encChoice == 1)
                            {
                                EncryptionUtility.DecryptFileAES(Path.Combine(currentDirectory, "Users", user.Username, downloadFileName), downloadDestination, key, iv);
                            }
                            else if (encChoice == 2)
                            {
                                EncryptionUtility.DecryptWithTripleDES(Path.Combine(currentDirectory, "Users", user.Username, downloadFileName), downloadDestination, key, iv);
                            }
                            else if (encChoice == 3)
                            {
                                EncryptionUtility.DecryptWithBlowfish(Path.Combine(currentDirectory, "Users", user.Username, downloadFileName), downloadDestination, key, iv);
                            }
                            else
                            {
                                Console.WriteLine("Pogrešan izbor.");
                                break;
                            }

                            if (FileSystemManager.VerifyFileSignature(downloadDestination, cert))
                            {
                                FileSystemManager.RemoveSignature(downloadDestination);
                                Console.WriteLine("Fajl uspješno preuzet.");
                            }
                            else
                            {
                                Console.WriteLine("Fajl nije validan");
                            }
                            break;

                        // Dijeljenje fajla
                        case 3:
                            Console.Write("Unesite putanju fajla za dijeljenje unutar vašeg korisničkog foldera: ");
                            string fileToShare = Console.ReadLine();

                            Console.Write("Unesite korisnika sa kojim želite podijeliti fajl: ");
                            string targetUsername = Console.ReadLine();

                            byte[] aesEncKey = key;
                            byte[] aesEncIV = iv;
                            string sharedFilePath = Path.Combine(currentDirectory, "Shared", $"{targetUsername}_{fileToShare}");

                            EncryptionUtility.EncryptFileAES(Path.Combine(currentDirectory, "Users", user.Username, fileToShare), sharedFilePath, key, iv);
                            
                            Console.WriteLine("Fajl uspješno podijeljen.");
                            break;

                        // Prikaz foldera i fajlova
                        case 4:
                            FileSystemManager.PrintDirectoryTree("Users/" + user.Username, "", true);
                            FileSystemManager.PrintDirectoryTreeFiltered(currentDirectory + "/Shared", "", true, user.Username);
                            break;

                        // Brisanje fajlova
                        case 5:
                            Console.Write("Unesite putanju fajla za brisanje unutar vašeg korisničkog foldera: ");
                            string fileToDeletePath = Console.ReadLine();
                            fileSystemManager.DeleteFile(fileToDeletePath);
                            break;

                        // Kreiranje foldera
                        case 6:
                            Console.Write("Unesite naziv novog foldera: ");
                            string newDirectoryPath = Console.ReadLine();
                            fileSystemManager.CreateDirectory(newDirectoryPath);
                            break;

                        // Brisanje foldera
                        case 7:
                            Console.Write("Unesite naziv direktorijuma koji želite da obrišete: ");
                            string toDeleteDirectoryPath = Console.ReadLine();
                            fileSystemManager.DeleteDirectory(toDeleteDirectoryPath);
                            break;

                        // Odjava
                        case 8:
                            Console.WriteLine("Odjava uspješna.");
                            pom = false;
                            break;

                        default:
                            Console.WriteLine("Nepoznata opcija. Pokušajte ponovo.");
                            break;
                    }
                }
            }
        }
    }
}

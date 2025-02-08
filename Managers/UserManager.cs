using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using KriptografijaProjekat.Managers.KriptografijaProjekat.Managers;
using KriptografijaProjekat.Models;
using KriptografijaProjekat.Utilities;
using Org.BouncyCastle.Asn1.X509;

namespace KriptografijaProjekat.Managers
{
    public class UserManager
    {
        private static readonly Dictionary<string, User> Users = new Dictionary<string, User>();
        private static readonly string UsersDirectoryPath = "Users"; // Putanja gde se čuvaju korisnički podaci (može biti fajl ili direktorijum)
        private readonly FileSystemManager _fileSystemManager;

        public UserManager(FileSystemManager fileSystemManager)
        {
            _fileSystemManager = fileSystemManager;
            LoadUsersFromDisk();
        }

        // Registracija korisnika
        public bool RegisterUser(string username, string password, string certificatePath)
        {
            if (Users.ContainsKey(username))
            {
                Console.WriteLine("Korisnik sa tim korisničkim imenom već postoji.");
                return false;
            }

            var user = new User
            {
                Username = username,
                PasswordHash = HashingUtility.HashWithSHA256(password),
                CertificatePath = Path.Combine(username, Path.GetFileName(certificatePath))
            };

            // Dodajemo korisnika u Dictionary
            Users[username] = user;

            // Kreiranje korisnickog direktorijumom
            _fileSystemManager.CreateDirectory(username);

            // Kopiramo sertifikat u korisnički folder
            string userCertificatePath = Path.Combine(UsersDirectoryPath, username, username + ".crt");
            File.Copy(certificatePath, userCertificatePath, true);

            // Čuvamo enkriptovanu lozinku u fajl
            string passwordFilePath = Path.Combine(UsersDirectoryPath, username, "password.enc");
            File.WriteAllText(passwordFilePath, HashingUtility.HashWithSHA256(password));

            Console.WriteLine("Korisnik uspješno registrovan.");
            return true;
        }

        // Prijava korisnika
        public User Login(string username, string password)
        {
            if (Users.ContainsKey(username))
            {
                var user = Users[username];
                
                string passwordFilePath = Path.Combine(UsersDirectoryPath, username, "password.enc");
                string filePass = File.ReadAllText(passwordFilePath);

                if (filePass == HashingUtility.HashWithSHA256(password))
                {
                    var certificate = new X509Certificate2(user.CertificatePath,"sigurnost");
                    if (!CertificateManager.IsCertificateRevoked(certificate))
                    {
                        Console.WriteLine("Prijava uspešna.");
                        return user;
                    }
                    else {
                        Console.WriteLine("Korisnikov sertifikat je povučen iz upotrebe."); 
                    }
                }
                else
                {
                    Console.WriteLine("Pogrešna lozinka.");
                }
            }
            else
            {
                Console.WriteLine("Korisnik sa tim korisničkim imenom ne postoji.");
            }
            return null;
        }

        // Ova funkcija se koristi za učitavanje korisničkih podataka sa diska
        public void LoadUsersFromDisk()
        {
            if (Directory.Exists(UsersDirectoryPath))
            {
                string[] userDirs = Directory.GetDirectories(UsersDirectoryPath);
                foreach (var dir in userDirs)
                {
                    string username = Path.GetFileName(dir);
                    string certificatePath = Path.Combine(dir, username + ".crt");
                    string passwordFilePath = Path.Combine(dir, "password.enc");

                    if (File.Exists(passwordFilePath))
                    {
                        string password = File.ReadAllText(passwordFilePath);
                        var user = new User
                        {
                            Username = username,
                            PasswordHash = password,
                            CertificatePath = certificatePath
                        };
                        Users[username] = user;
                    }
                }
            }
        }
    }
}

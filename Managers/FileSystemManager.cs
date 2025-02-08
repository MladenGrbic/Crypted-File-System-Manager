using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using KriptografijaProjekat.Utilities;

namespace KriptografijaProjekat.Managers
{
    public class FileSystemManager
    {
        private readonly string _baseDirectory;
        private readonly string _sharedDirectory;

        public FileSystemManager(string baseDirectory)
        {
            _baseDirectory = baseDirectory;
            string currentDirectory = Directory.GetCurrentDirectory();
            _sharedDirectory = Path.Combine(currentDirectory, "Shared");
            Directory.CreateDirectory(_sharedDirectory);
        }

        public void CreateDirectory(string path)
        {
            string fullPath = Path.Combine(_baseDirectory, path);
            Directory.CreateDirectory(fullPath);
        }

        public void DeleteDirectory(string path)
        {
            string fullPath = Path.Combine(_baseDirectory, path);
            Directory.Delete(fullPath, true);
        }

        public void DeleteFile(string path)
        {
            string fullPath = Path.Combine(_baseDirectory, path);
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
            }
        }

        // Ispis za korisnicki direktorijum
        public static void PrintDirectoryTree(string dir, string indent, bool isLast)
        {
            string marker = isLast ? "└── " : "├── ";
            Console.WriteLine(indent + marker + new DirectoryInfo(dir).Name);

            string newIndent = indent + (isLast ? "    " : "│   ");

            string[] subDirectories = Directory.GetDirectories(dir);
            string[] files = Directory.GetFiles(dir);

            for (int i = 0; i < subDirectories.Length; i++)
            {
                PrintDirectoryTree(subDirectories[i], newIndent, i == subDirectories.Length - 1 && files.Length == 0);
            }

            string[] allowedExtensions = { ".txt", ".jpg", ".png", ".pdf" };

            var filteredFiles = files.Where(file => allowedExtensions.Contains(Path.GetExtension(file).ToLower())).ToArray();
            if (filteredFiles.Length > 0)
            {
                for (int i = 0; i < filteredFiles.Length; i++)
                {
                    string fileMarker = (i == filteredFiles.Length - 1) ? "└── " : "├── "; 
                    Console.WriteLine(newIndent + fileMarker + Path.GetFileName(filteredFiles[i]));

                }
            }
        }

        public static void SignFileAndAppend(string filePath, X509Certificate2 cert)
        {
            // Učitaj podatke fajla
            byte[] fileData = File.ReadAllBytes(filePath);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(fileData);

                // Potpiši heš sa privatnim ključem sertifikata (RSA 2048)
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    // Potpisivanje sa RSA 2048-bitnim ključem
                    byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    // Dodaj potpis na kraj fajla
                    using (FileStream fs = new FileStream(filePath, FileMode.Append))
                    {
                        fs.Write(signature, 0, signature.Length);
                    }

                    Console.WriteLine($"Fajl je uspešno potpisan i potpis je dodat na kraj: {filePath}");
                }
            }
        }

        public static bool VerifyFileSignature(string filePath, X509Certificate2 cert)
        {
            // Učitaj sadržaj fajla
            byte[] fileData = File.ReadAllBytes(filePath);

            int signatureLength = 256; 
            byte[] fileContent = new byte[fileData.Length - signatureLength];
            byte[] signature = new byte[signatureLength];

            Array.Copy(fileData, 0, fileContent, 0, fileContent.Length);
            Array.Copy(fileData, fileContent.Length, signature, 0, signature.Length);

            // Koristi SHA256 heširanje za generisanje heša originalnog fajla
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(fileContent);

                // Verifikuj potpis koristeći javni ključ sertifikata
                using (RSA rsa = cert.GetRSAPublicKey())
                {
                    bool isValid = rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    return isValid; // Vraća true ako je potpis validan, inače false
                }
            }
        }

        public static void RemoveSignature(string filePath)
        {
            // Učitaj podatke fajla
            byte[] fileData = File.ReadAllBytes(filePath);

            // Dužina potpisa (RSA 2048 = 256 bajtova)
            int signatureLength = 256;

            // Kreiraj novi fajl bez potpisa
            byte[] fileWithoutSignature = new byte[fileData.Length - signatureLength];
            Array.Copy(fileData, 0, fileWithoutSignature, 0, fileWithoutSignature.Length);

            File.WriteAllBytes(filePath, fileWithoutSignature);

            Console.WriteLine($"Potpis je uspešno uklonjen sa fajla: {filePath}");
        }

        // Ispis za Shared folder
        public static void PrintDirectoryTreeFiltered(string dir, string indent, bool isLast, string username)
        {
            string[] allowedExtensions = { ".txt", ".jpg", ".png", ".pdf" };

            string[] files = Directory.GetFiles(dir)
                .Where(file => allowedExtensions.Contains(Path.GetExtension(file).ToLower()) &&
                               Path.GetFileName(file).ToLower().Contains(username.ToLower()))
                .ToArray();

            void CustomPrintDirectoryTree(string dirPath, string ind, bool last)
            {
                string marker = last ? "└── " : "├── ";
                Console.WriteLine(ind + marker + new DirectoryInfo(dirPath).Name);

                string newIndent = ind + (last ? "    " : "│   ");

                string[] subDirectories = Directory.GetDirectories(dirPath);

                for (int i = 0; i < subDirectories.Length; i++)
                {
                    CustomPrintDirectoryTree(subDirectories[i], newIndent, i == subDirectories.Length - 1 && files.Length == 0);
                }

                for (int i = 0; i < files.Length; i++)
                {
                    string fileMarker = (i == files.Length - 1) ? "└── " : "├── ";
                    Console.WriteLine(newIndent + fileMarker + Path.GetFileName(files[i]));
                }
            }
            CustomPrintDirectoryTree(dir, indent, isLast);
        }

    }

}

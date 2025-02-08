using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace KriptografijaProjekat.Managers
{
    namespace KriptografijaProjekat.Managers
    {
        public class CertificateManager
        {
            private X509Certificate2 _caCertificate;
            private static List<string> _crl;

            public CertificateManager(string caCertificatePath, string crlPath)
            {
                _caCertificate = new X509Certificate2(caCertificatePath);
                _crl = File.ReadAllLines(crlPath).ToList();
            }

            // Provjera da li je sertifikat ponisten
            public static bool IsCertificateRevoked(X509Certificate2 certificate)
            {
                string serialNumber = certificate.SerialNumber;
                return _crl.Contains(serialNumber);
            }

            // Validiranje sertifikata
            public bool ValidateCertificate(string certificatePath)
            {
                var certificate = new X509Certificate2(certificatePath, "sigurnost");

                if (IsCertificateRevoked(certificate))
                {
                    return false;
                }
                var caCertificate = new X509Certificate2(_caCertificate);
                bool isValid = !certificate.Verify();
                bool isIssuedByCa = certificate.Issuer == caCertificate.Subject;

                return isValid && isIssuedByCa;
            }

            // Izdvoji sertifikat iz fajla
            public X509Certificate2 GetCertificateFromFile(string certificatePath)
            {
                return new X509Certificate2(certificatePath, "sigurnost");
            }

            // Potvrda potpisa
            public bool ValidateSignature(X509Certificate2 certificate)
            {
                return certificate.Verify();
            }
        }
    }

}

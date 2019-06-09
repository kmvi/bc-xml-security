using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace _SignedXml.Samples
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Signature verification test");
            Console.WriteLine("----------------------------------------------------------------");
            var test1 = new SigningAndVerifying();
            test1.SignedXmlHasVerifiableSignature();

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Signature verification test with custom signature method");
            Console.WriteLine("----------------------------------------------------------------");
            var test2 = new SigningAndVerifyingWithCustomSignatureMethod();
            test2.SignedXmlHasVerifiableSignature();

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Signature verification test using x509 certificate");
            Console.WriteLine("----------------------------------------------------------------");
            var test3 = new SigningVerifyingX509Cert();
            test3.SignedXmlHasCertificateVerifiableSignature();

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Signature verification test using GOST algorithm");
            Console.WriteLine("----------------------------------------------------------------");
            var test3_1 = new SigningVerifyingGost();
            test3_1.SignedXmlHasCertificateVerifiableSignature();

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Encryption/decryption test using symmetric algorithms");
            Console.WriteLine("----------------------------------------------------------------");
            var test4 = new EncryptingAndDecryptingSymmetric();
            test4.SymmetricEncryptionRoundtrip();

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Encryption/decryption test using symmetric algorithms with key wrap");
            Console.WriteLine("----------------------------------------------------------------");
            var test5 = new EncryptingDecryptingSymmetricKeyWrap();
            test5.SymmetricKeyWrapEncryptionRoundtrip();

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Encryption/decryption test using RSA");
            Console.WriteLine("----------------------------------------------------------------");
            var test6 = new EncryptingAndDecryptingAsymmetric();
            test6.AsymmetricEncryptionRoundtrip();
        }
    }
}

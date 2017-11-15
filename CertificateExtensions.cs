using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace System.Security.Cryptography.Xml
{
    static class CertificateExtensions
    {
        public static RSA GetRSAPublicKey(this X509Certificate2 cert)
        {
            throw new NotImplementedException();
        }

        public static RSA GetRSAPrivateKey(this X509Certificate2 cert)
        {
            throw new NotImplementedException();
        }
    }
}

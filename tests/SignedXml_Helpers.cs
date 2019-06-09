// Licensed to the .NET Foundation under one or more agreements.
// See the LICENSE file in the project root for more information.

using System.Xml;
using Xunit;

namespace Org.BouncyCastle.Crypto.Xml.Tests
{
    public static class Helpers
    {
        public static bool VerifyCryptoExceptionOnLoad(string xml, bool loadXmlThrows)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(xml);

            var signatureNode = (XmlElement)xmlDoc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0];

            SignedXml signedXml = new SignedXml(xmlDoc);
            if (loadXmlThrows)
                Assert.Throws<System.Security.Cryptography.CryptographicException>(() => signedXml.LoadXml(signatureNode));
            else
                signedXml.LoadXml(signatureNode);

            if (!loadXmlThrows)
            {
                bool checkSigResult = signedXml.CheckSignature();
                return checkSigResult;
            }
            return false;
        }
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Linq;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Xml;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace _SignedXml.Samples
{
    public class SigningVerifyingGost
    {
        const string ExampleXml = @"<?xml version=""1.0""?>
<example>
<test>some text node</test>
</example>";

        private static void SignXml(XmlDocument doc, X509Certificate cert, AsymmetricKeyParameter key)
        {
            var signedXml = new SignedXml(doc)
            {
                SigningKey = key,
            };

            // Note: Adding KeyInfo (KeyInfoX509Data) does not provide more security
            //       Signing with private key is enough

            var reference = new Reference();
            reference.Uri = "";
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.DigestMethod = SignedXml.XmlDsigGost3411_2012_512_Url;
            signedXml.AddReference(reference);

            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));

            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigGost3410_2012_512_Url;

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
        }

        private static bool VerifyXml(string signedXmlText, X509Certificate certificate)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(signedXmlText);

            SignedXml signedXml = new SignedXml(xmlDoc);
            var signatureNode = (XmlElement)xmlDoc.GetElementsByTagName("Signature")[0];
            signedXml.LoadXml(signatureNode);

            // Note: `verifySignatureOnly: true` should not be used in the production
            //       without providing application logic to verify the certificate.
            // This test bypasses certificate verification because:
            // - certificates expire - test should not be based on time
            // - we cannot guarantee that the certificate is trusted on the machine
            return signedXml.CheckSignature(/*certificate, verifySignatureOnly: true*/);
        }

        public void SignedXmlHasCertificateVerifiableSignature()
        {
            var x509cert = GetSampleX509Certificate();
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(ExampleXml);

            SignXml(xmlDoc, x509cert.Item1, x509cert.Item2);

            Console.WriteLine("Signed document:");
            Console.WriteLine();
            Console.WriteLine(xmlDoc.OuterXml);

            var result = VerifyXml(xmlDoc.OuterXml, x509cert.Item1);

            Console.WriteLine();
            Console.WriteLine("Signature verification result: {0}", result ? "valid" : "invalid");
            Console.WriteLine();
        }

        private static readonly byte[] SamplePfx = Convert.FromBase64String(
    @"MIIEBAIBAzCCA74GCSqGSIb3DQEHAaCCA68EggOrMIIDpzCCARQGCSqGSIb3DQEHAaCCAQUEggEBMIH+MIH7BgsqhkiG9w0BDAoBAqCBnzCBnDAoBgoqhkiG9w0BDAEDMBoEFOoVd1NZegNmSdTfsYdjsOvrBag9AgIEAARwMP3TR+ZVx43TT3oXLiZFwJ235wABFHLxyLafWjm9vh2LFBKizdDhhFswYw5JtS/mMzS31m0G8idt8ZqUVRvyY48Cj8owVux/GQKEBJiBXSWan/vJcyStmdyAPWT6nX3JovZbygV6hQ8hIYJSqdooHjFKMCMGCSqGSIb3DQEJFDEWHhQAcwBvAG0AZQBfAGEAbABpAGEAczAjBgkqhkiG9w0BCRUxFgQU4KpA63u8ZLl6qqN6e0Ho0eQf7+MwggKLBgkqhkiG9w0BBwagggJ8MIICeAIBADCCAnEGCSqGSIb3DQEHATAoBgoqhkiG9w0BDAEGMBoEFOfYAMM76AbtANos+bwWIghKTG1/AgIEAICCAjgdU4MBcjbKoswdhfZGGR+6KcJPuu3X9JdtWS/SXO9aE0iwxaq63QCcbrgztKNb3FiHzwrMACQUEAWRAaG9uQC8HFBm+bRuyTRqDpojhtM6HO0xhXBwHjWuVnSRwiVcv3Mxke/FF26I99VwOYjVADg4AIqnH/G9AbIpXAyFvvIITtlMGsQ5tglaXwoJgQRwG21/kQHsjRh6YyQpZ3MQTxLJVw8Go9Euj97oOsSZMESedh+Aph9O1AiqglHzY1ercIsP9UKaqn719yvHusezAA+67WRyWJkE3h7jgt4r73dQ4CE4u5xrsAbWZxREPNETIGC5B3JOK69SNlMDd5Q2fMMmRLgjZKrp68LM/RdHORXTUXLAJ4LTlwxIHTcrg2vnFXjFnNcOkpDNUlqIr94bhBwJJS+hlODVAGeCtqnxJvSSyjMvXUwrxqf4n8DZ1618G6TzHX+Btad9XUo9TKis7bDSXSVpy8YyqFclqN8X9JxFsS7sYZJXiJuL8uV8V68jhAzNWEyWChqNtdWQqlAEwVE/j5VDW2F26Frunr+b6hstQJJJvBFmpqzeSiD97JNUHxxIjuTehsxIQNPqc8NNHHrCmS9ZVsnrLRlKR5CedRGESj5AoEtt1nzXa+sErXzQbRmms1HfQrEKRCsUhbYa5N6notYpGb3J5Xw4uQgXcot45s3K+n1b/FEjfi/Cv4NeUvHHADPvScOVvWFL3bOjJ7uMfzHhFl9HavW+JsZrUUc6NgpvZvlMFBSHMD0wITAJBgUrDgMCGgUABBS6V9yM+KworvFGNEXd6WeP1EiZ9QQUUx4f9Eu9RABlDOBVIOGHaVlc9EUCAgQA");

        public static Tuple<X509Certificate, AsymmetricKeyParameter> GetSampleX509Certificate()
        {
            // To generate self-signed certificate, see GostUtilities.cs

            Pkcs12Store store = new Pkcs12Store();

            char[] password = "mono".ToCharArray();
            using (MemoryStream ms = new MemoryStream(SamplePfx))
                store.Load(ms, password);

            string alias = store.Aliases.Cast<string>().First();
            X509Certificate cert = store.GetCertificate(alias).Certificate;
            AsymmetricKeyParameter privKey = store.GetKey(alias).Key;

            return Tuple.Create(cert, privKey);
        }
    }
}

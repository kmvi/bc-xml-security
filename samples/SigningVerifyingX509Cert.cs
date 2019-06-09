// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Xml;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace _SignedXml.Samples
{
    public class SigningVerifyingX509Cert
    {
        const string ExampleXml = @"<?xml version=""1.0""?>
<example>
<test>some text node</test>
</example>";
        
        private static void SignXml(XmlDocument doc, AsymmetricKeyParameter key)
        {
            var signedXml = new SignedXml(doc)
            {
                SigningKey = key
            };

            // Note: Adding KeyInfo (KeyInfoX509Data) does not provide more security
            //       Signing with private key is enough

            var reference = new Reference();
            reference.Uri = "";
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

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
            return signedXml.CheckSignature(certificate, verifySignatureOnly: true);
        }

        public void SignedXmlHasCertificateVerifiableSignature()
        {
            var x509cert = GetSampleX509Certificate();
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(ExampleXml);

            SignXml(xmlDoc, x509cert.Item2);

            Console.WriteLine("Signed document:");
            Console.WriteLine();
            Console.WriteLine(xmlDoc.OuterXml);

            var result = VerifyXml(xmlDoc.OuterXml, x509cert.Item1);

            Console.WriteLine();
            Console.WriteLine("Signature verification result: {0}", result ? "valid" : "invalid");
            Console.WriteLine();
        }

        private static readonly byte[] SamplePfx = Convert.FromBase64String(
    @"MIIFpQIBAzCCBV8GCSqGSIb3DQEHAaCCBVAEggVMMIIFSDCCAl8GCSqGSIb3DQEHBqCCAlAwggJMAgEAMIICRQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIGTfVa4+vR1UCAgfQgIICGJuFE9alFWJFkaoeewKDIEnVwRxXfMsi8dcySYnp7jljEUQBfW/GIbOf7Lg2nHd0qxvxYI2YL4Zs+d0jWbqfNHamGFCMPe1dK957Z2PsKXR183vMSgnmlLAHktsIN+Gor7q1GbQ4ljfZkGqZ/rkgUsgsSYZSnJevP/uH0VnvxemljVJ7N7gKMYO0aqrca4qJ0O4YxBYyaerPFUOYunQlvk6DOF3SQXza5oFKcPGrSpE/9eQrnmm64BtbdnUE6qqEjfZfNa6MOD3vOnapLUBsel2TtVCu8tEl7I8FGxozTLXVTXOBkL3k7xLRS52ZtpbcU2JIhlDGpxeFXmjKYzdzHoL20iJubfdkUYtHwB0XjBKKLcI7jfgGgjNauaTLAx8FF+5O9s7Zbj2+SKWv56kqAwdX+iH21VgjAN9EByIXHb3p2ZOvy4ONDXTmfSn7jbuPLZTi+u6bxn2JOLf/gjEA8FiCuQDL9gF247bnUq08Z1uzuAUeaPL13U8mxwEuvCOXx5NEQIuf3cusnaH4+7uIhPk5tnfA5XOaABySetRjZhVN5dC5/g3KTwmaDamlW3Y7Az/NzAC4uKa2ny5jwYKBgHviEKOyJfLDKr5fOMRToOfgxvAdXZohQQTE1+TcBjp+eeV5koDfB1ReCKIRHugPZu5j9SCVcYanwFeJ5M4cEHZ9U1Ytsmzjh0fwV17D/hxQ4aS4VwVpOMypMIIC4QYJKoZIhvcNAQcBoIIC0gSCAs4wggLKMIICxgYLKoZIhvcNAQwKAQKgggKeMIICmjAcBgoqhkiG9w0BDAEDMA4ECBRdKqx022cfAgIH0ASCAnjZx9fvPCHizdH6apVzWWmfy/84HvDPjFOUV1TPehTnDPkNpF/uK/ya4jlbl4Kw0Zfknt5Xydl89SMXIWa2q+nWmxyG3XyfGqOAeBfJBSdCF5K3qkZZnzEfraKZZ5Hh8IEmK+ey45O6sltua6Xl5MRBmKLiwma7vX4ihXQTMfb0WlWDYCXZi85OeF0OlUjRWAwz4PeeiBK4nmI/vNmF1EzDVdZGkrrE8mot3Y4z6bvwqip2tUUbHuMnC+/1ikAcJzCOw4NpnEWCRtIJxgJ9es8E8CUfHESnWKe4nh6tJVJ15B8/7oF7N6j7oq4Oj346JthKoWWkzifNaH79A60/uFh08Rv7zrtJf6kedY6Ve2bR5lhWn0cv9Q6IaoqTmKKTmKJnjdQO9lKRCR6iI2OsYtXBropD8xhNNqsyfpNmP0G6wFiEZZxZjWOkZEJLUzFbH+Su+7l2l4FN9sM7k211/l3/3YF1QJHwZsgL98DZL4qE+nkuZQcdtOUx8QTyTOcVb3IzgCAwZm0rgdXQpJ9yRBgOC/6MnqaCPI0jJuavXF/a28GJWWGlazx7SWTrbzNVJ83ZhQ+pfPEPtMi3t0YVLLvapu3otgpiMkv4ew/ssXwYbg6xBWfotK+NG1cPwVFy9/V9+H5dpdvRI/le2QG0F5xCfCeKh/3AuNiMPEGoVUR5kj5cwFK6eskvt/+74ZenxfNPZ2Uttiw8DsqtTx1gxhcSZeU5YWpO7O78RaYE4Ll4kPbbvIaR18Napb6NKP846z02zvaw+feXARLe0HUY58TlmUjSX3MZRK4PEdyMIQ/URyPimj4rImaDfFrKPAHIjqT3EKv+KuNs8TEVMBMGCSqGSIb3DQEJFTEGBAQBAAAAMD0wITAJBgUrDgMCGgUABBRZOo132cuo2zNyy+SH2c+pN4OGmQQU2nQao3je7DTj2G6Gge8pooPf2ncCAgfQ");

        public static Tuple<X509Certificate, AsymmetricKeyParameter> GetSampleX509Certificate()
        {
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

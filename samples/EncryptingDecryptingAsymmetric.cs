// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Xml;
using Org.BouncyCastle.Security;

namespace _SignedXml.Samples
{
    // Simplified implementation of MSDN sample:
    // https://msdn.microsoft.com/en-us/library/ms229746(v=vs.110).aspx
    public class EncryptingAndDecryptingAsymmetric
    {
        private static XmlDocument LoadXmlFromString(string xml)
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(xml);
            return doc;
        }

        private static void Encrypt(XmlDocument doc, string elementName, string encryptionElementID, RsaKeyParameters rsaKey, string keyName, bool useOAEP)
        {
            var elementToEncrypt = (XmlElement)doc.GetElementsByTagName(elementName)[0];

            var sessionKeyData = EncryptingAndDecryptingSymmetric.GenerateBlock(256);
            var sessionKeyIV = EncryptingAndDecryptingSymmetric.GenerateBlock(128);
            var sessionKey = new ParametersWithIV(new KeyParameter(sessionKeyData), sessionKeyIV);

            // Encrypt the session key and add it to an EncryptedKey element.
            var encryptedKey = new EncryptedKey()
            {
                CipherData = new CipherData(EncryptedXml.EncryptKey(sessionKeyData, rsaKey, useOAEP)),
                EncryptionMethod = new EncryptionMethod(useOAEP ? EncryptedXml.XmlEncRSAOAEPUrl : EncryptedXml.XmlEncRSA15Url)
            };

            // Specify which EncryptedData
            // uses this key. An XML document can have
            // multiple EncryptedData elements that use
            // different keys.
            encryptedKey.AddReference(new DataReference()
            {
                Uri = "#" + encryptionElementID
            });

            var encryptedData = new EncryptedData()
            {
                Type = EncryptedXml.XmlEncElementUrl,
                Id = encryptionElementID,

                // Create an EncryptionMethod element so that the
                // receiver knows which algorithm to use for decryption.
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
            };

            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
            encryptedKey.KeyInfo.AddClause(new KeyInfoName()
            {
                Value = keyName
            });

            var encryptedXml = new EncryptedXml();
            encryptedData.CipherData.CipherValue = encryptedXml.EncryptData(elementToEncrypt, sessionKey, false);

            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);
        }

        public static void Decrypt(XmlDocument doc, RsaKeyParameters rsaKey, string keyName)
        {
            var encrypted = new EncryptedXml(doc);
            encrypted.AddKeyNameMapping(keyName, rsaKey);
            encrypted.DecryptDocument();
        }

        public void AsymmetricEncryptionRoundtrip(bool useOAEP)
        {
            const string exampleXmlRootElement = "example";
            const string exampleXml = @"<?xml version=""1.0""?>
<example>
<test>some text node</test>
</example>";

            var keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var key = keyGen.GenerateKeyPair();

            XmlDocument xmlDocToEncrypt = LoadXmlFromString(exampleXml);
            Encrypt(xmlDocToEncrypt, exampleXmlRootElement, "EncryptedElement1", (RsaKeyParameters)key.Public, "rsaKey", useOAEP);

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Use OAEP: {0}", useOAEP);
            Console.WriteLine("Encrypted document:");
            Console.WriteLine();
            Console.WriteLine(xmlDocToEncrypt.OuterXml);
            Console.WriteLine();

            XmlDocument xmlDocToDecrypt = LoadXmlFromString(xmlDocToEncrypt.OuterXml);
            Decrypt(xmlDocToDecrypt, (RsaKeyParameters)key.Private, "rsaKey");

            Console.WriteLine("Decrypted document:");
            Console.WriteLine();
            Console.WriteLine(xmlDocToDecrypt.OuterXml);
            Console.WriteLine();
        }

        public void AsymmetricEncryptionRoundtrip()
        {
            AsymmetricEncryptionRoundtrip(false);
            AsymmetricEncryptionRoundtrip(true); // OAEP is recommended
        }
    }
}

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

namespace _SignedXml.Samples
{
    public class EncryptingDecryptingSymmetricKeyWrap
    {
        private static XmlDocument LoadXmlFromString(string xml)
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(xml);
            return doc;
        }

        private static void Encrypt(XmlDocument doc, string elementName, string encryptionElementID, ICipherParameters key, string keyName, Func<ICipherParameters> innerKeyFactory)
        {
            var elementToEncrypt = (XmlElement)doc.GetElementsByTagName(elementName)[0];

            ICipherParameters innerKey = innerKeyFactory();
            // Encrypt the key with another key
            var encryptedKey = new EncryptedKey()
            {
                CipherData = new CipherData(EncryptedXml.EncryptKey(((KeyParameter)((ParametersWithIV)innerKey).Parameters).GetKey(), (KeyParameter)((ParametersWithIV)key).Parameters)),
                EncryptionMethod = new EncryptionMethod(EncryptingAndDecryptingSymmetric.GetEncryptionMethodName(key, keyWrap: true))
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
                EncryptionMethod = new EncryptionMethod(EncryptingAndDecryptingSymmetric.GetEncryptionMethodName(innerKey, keyWrap: false))
            };

            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
            encryptedKey.KeyInfo.AddClause(new KeyInfoName()
            {
                Value = keyName
            });

            var encryptedXml = new EncryptedXml();
            encryptedData.CipherData.CipherValue = encryptedXml.EncryptData(elementToEncrypt, innerKey, false);

            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);
        }

        public static void Decrypt(XmlDocument doc, ICipherParameters key, string keyName)
        {
            var encrypted = new EncryptedXml(doc);
            encrypted.AddKeyNameMapping(keyName, key);
            encrypted.DecryptDocument();
        }

        public void SymmetricKeyWrapEncryptionRoundtrip(Func<ICipherParameters> keyFactory, Func<ICipherParameters> innerKeyFactory)
        {
            const string exampleXmlRootElement = "example";
            const string exampleXml = @"<?xml version=""1.0""?>
<example>
<test>some text node</test>
</example>";
            const string keyName = "mytestkey";

            ICipherParameters key = keyFactory();
            XmlDocument xmlDocToEncrypt = LoadXmlFromString(exampleXml);
            Encrypt(xmlDocToEncrypt, exampleXmlRootElement, "EncryptedElement1", key, keyName, innerKeyFactory);

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine("Algorithm: {0}", EncryptingAndDecryptingSymmetric.GetEncryptionMethodName(key, keyWrap: true));
            Console.WriteLine("Encrypted document:");
            Console.WriteLine();
            Console.WriteLine(xmlDocToEncrypt.OuterXml);
            Console.WriteLine();

            XmlDocument xmlDocToDecrypt = LoadXmlFromString(xmlDocToEncrypt.OuterXml);
            Decrypt(xmlDocToDecrypt, key, keyName);

            Console.WriteLine("Decrypted document:");
            Console.WriteLine();
            Console.WriteLine(xmlDocToDecrypt.OuterXml);
            Console.WriteLine();
        }

        public void SymmetricKeyWrapEncryptionRoundtrip()
        {
            // DES is not supported in keywrap scenario, there is no specification string for it either
            foreach (var factory in EncryptingAndDecryptingSymmetric.GetSymmetricAlgorithms(skipDes: true))
                foreach (var innerFactory in EncryptingAndDecryptingSymmetric.GetSymmetricAlgorithms(skipDes: true))
                    SymmetricKeyWrapEncryptionRoundtrip(factory, innerFactory);
        }
    }
}

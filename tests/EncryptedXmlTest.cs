// Licensed to the .NET Foundation under one or more agreements.
// See the LICENSE file in the project root for more information
//
// EncryptedXmlTest.cs
//
// Author:
//	Atsushi Enomoto  <atsushi@ximian.com>
//
// Copyright (C) 2006 Novell, Inc (http://www.novell.com)
//
// Licensed to the .NET Foundation under one or more agreements.
// See the LICENSE file in the project root for more information.


using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace Org.BouncyCastle.Crypto.Xml.Tests
{
    public class EncryptedXmlTest
    {
        private static readonly Encoding DefaultEncoding = Encoding.UTF8;
        private const string DefaultCipherMode = "CBC";
        private const string DefaultPaddingMode = "ISO10126PADDING";
        private const string DefaultRecipient = "";
        private static readonly XmlResolver DefaultXmlResolver = null;
        private const int DefaultXmlDSigSearchDepth = 20;

        [Fact]
        public void Constructor_Default()
        {
            EncryptedXml encryptedXml = new EncryptedXml();
            Assert.Equal(DefaultEncoding, encryptedXml.Encoding);
            Assert.Equal(DefaultCipherMode, encryptedXml.Mode);
            Assert.Equal(DefaultPaddingMode, encryptedXml.Padding);
            Assert.Equal(DefaultRecipient, encryptedXml.Recipient);
            Assert.Equal(DefaultXmlResolver, encryptedXml.Resolver);
            Assert.Equal(DefaultXmlDSigSearchDepth, encryptedXml.XmlDSigSearchDepth);
        }

        [Fact]
        public void Constructor_XmlDocument()
        {
            EncryptedXml encryptedXml = new EncryptedXml(null);
            Assert.Equal(DefaultEncoding, encryptedXml.Encoding);
            Assert.Equal(DefaultCipherMode, encryptedXml.Mode);
            Assert.Equal(DefaultPaddingMode, encryptedXml.Padding);
            Assert.Equal(DefaultRecipient, encryptedXml.Recipient);
            Assert.Equal(DefaultXmlResolver, encryptedXml.Resolver);
            Assert.Equal(DefaultXmlDSigSearchDepth, encryptedXml.XmlDSigSearchDepth);
        }

        [Theory]
        [InlineData("Org.BouncyCastle.Crypto.Xml.Tests.EncryptedXmlSample1.xml")]
        [InlineData("Org.BouncyCastle.Crypto.Xml.Tests.EncryptedXmlSample3.xml")]
        public void RsaDecryption(string resourceName)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string originalXml;
            using (Stream stream = TestHelpers.LoadResourceStream(resourceName))
            using (StreamReader streamReader = new StreamReader(stream))
            {
                originalXml = streamReader.ReadToEnd();
                doc.LoadXml(originalXml);
            }

            EncryptedXml encxml = new EncryptedXml(doc);
            var certificate = TestHelpers.GetSampleX509Certificate();
            var rsaKey = certificate.Item2 as RsaKeyParameters;
            Assert.NotNull(rsaKey);

            XmlNamespaceManager nm = new XmlNamespaceManager(doc.NameTable);
            nm.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
            nm.AddNamespace("o", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            nm.AddNamespace("e", EncryptedXml.XmlEncNamespaceUrl);
            XmlElement el = doc.SelectSingleNode("/s:Envelope/s:Header/o:Security/e:EncryptedKey", nm) as XmlElement;
            EncryptedKey ekey = new EncryptedKey();
            ekey.LoadXml(el);

            var rsa = CipherUtilities.GetCipher("RSA//OAEPPADDING");
            rsa.Init(false, rsaKey);
            byte[] key = rsa.DoFinal(ekey.CipherData.CipherValue);

            var aes = CipherUtilities.GetCipher("AES/CBC/PKCS7PADDING");
            var random = new SecureRandom();
            var ivdata = new byte[aes.GetBlockSize()];
            random.NextBytes(ivdata);
            var param = new ParametersWithIV(new KeyParameter(key), ivdata);

            List<XmlElement> elements = new List<XmlElement>();
            foreach (XmlElement encryptedDataElement in doc.SelectNodes("//e:EncryptedData", nm))
            {
                elements.Add(encryptedDataElement);
            }
            foreach (XmlElement encryptedDataElement in elements)
            {
                EncryptedData edata = new EncryptedData();
                edata.LoadXml(encryptedDataElement);
                encxml.ReplaceData(encryptedDataElement, encxml.DecryptData(edata, param));
            }
        }

        [Fact]
        public void Sample2()
        {
            var aes = CipherUtilities.GetCipher("AES/CBC/ZEROBYTEPADDING");
            var random = new SecureRandom();
            var ivdata = new byte[aes.GetBlockSize()];
            var keydata = Convert.FromBase64String("o/ilseZu+keLBBWGGPlUHweqxIPc4gzZEFWr2nBt640=");
            random.NextBytes(ivdata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(TestHelpers.LoadResourceStream("Org.BouncyCastle.Crypto.Xml.Tests.EncryptedXmlSample2.xml"));
            EncryptedXml encxml = new EncryptedXml(doc);
            EncryptedData edata = new EncryptedData();
            edata.LoadXml(doc.DocumentElement);
            encxml.ReplaceData(doc.DocumentElement, encxml.DecryptData(edata, param));
        }

        [Fact]
        public void RoundtripSample1()
        {
            using (StringWriter sw = new StringWriter())
            {

                // Encryption
                {
                    XmlDocument doc = new XmlDocument();
                    doc.PreserveWhitespace = true;
                    doc.LoadXml("<root>  <child>sample</child>   </root>");

                    XmlElement body = doc.DocumentElement;

                    var aes = CipherUtilities.GetCipher("AES/CBC/ZEROBYTEPADDING");
                    var ivdata = Convert.FromBase64String("pBUM5P03rZ6AE4ZK5EyBrw==");
                    var keydata = Convert.FromBase64String("o/ilseZu+keLBBWGGPlUHweqxIPc4gzZEFWr2nBt640=");
                    var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

                    EncryptedXml exml = new EncryptedXml();
                    byte[] encrypted = exml.EncryptData(body, param, false);
                    EncryptedData edata = new EncryptedData();
                    edata.Type = EncryptedXml.XmlEncElementUrl;
                    edata.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
                    EncryptedKey ekey = new EncryptedKey();
                    // omit key encryption, here for testing
                    byte[] encKeyBytes = keydata;
                    ekey.CipherData = new CipherData(encKeyBytes);
                    ekey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
                    DataReference dr = new DataReference();
                    dr.Uri = "_0";
                    ekey.AddReference(dr);
                    edata.KeyInfo.AddClause(new KeyInfoEncryptedKey(ekey));
                    ekey.KeyInfo.AddClause(new RSAKeyValue());
                    edata.CipherData.CipherValue = encrypted;
                    EncryptedXml.ReplaceElement(doc.DocumentElement, edata, false);
                    doc.Save(new XmlTextWriter(sw));
                }

                // Decryption
                {
                    var aes = CipherUtilities.GetCipher("AES/CBC/ZEROBYTEPADDING");
                    var random = new SecureRandom();
                    var ivdata = new byte[aes.GetBlockSize()];
                    var keydata = Convert.FromBase64String("o/ilseZu+keLBBWGGPlUHweqxIPc4gzZEFWr2nBt640=");
                    random.NextBytes(ivdata);
                    var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

                    XmlDocument doc = new XmlDocument();
                    doc.PreserveWhitespace = true;
                    doc.LoadXml(sw.ToString());
                    EncryptedXml encxml = new EncryptedXml(doc);
                    EncryptedData edata = new EncryptedData();
                    edata.LoadXml(doc.DocumentElement);
                    encxml.ReplaceData(doc.DocumentElement, encxml.DecryptData(edata, param));
                }
            }
        }

        [Fact]
        public void Encrypt_DecryptDocument_AES()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string xml = "<root>  <child>sample</child>   </root>";
            doc.LoadXml(xml);

            var aes = CipherUtilities.GetCipher("AES/CBC/ZEROBYTEPADDING");
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            EncryptedXml exml = new EncryptedXml();
            exml.AddKeyNameMapping("aes", param);
            EncryptedData ed = exml.Encrypt(doc.DocumentElement, "aes");

            doc.LoadXml(ed.GetXml().OuterXml);
            EncryptedXml exmlDecryptor = new EncryptedXml(doc);
            exmlDecryptor.AddKeyNameMapping("aes", param);
            exmlDecryptor.DecryptDocument();

            Assert.Equal(xml, doc.OuterXml);
        }

        [Fact]
        public void Encrypt_X509()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string xml = "<root>  <child>sample</child>   </root>";
            doc.LoadXml(xml);

            var certificate = TestHelpers.GetSampleX509Certificate();
            EncryptedXml exml = new EncryptedXml();
            EncryptedData ed = exml.Encrypt(doc.DocumentElement, certificate.Item1);

            Assert.NotNull(ed);

            doc.LoadXml(ed.GetXml().OuterXml);
            XmlNamespaceManager nm = new XmlNamespaceManager(doc.NameTable);
            nm.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);

            Assert.NotNull(doc.SelectSingleNode("//enc:EncryptedKey", nm));
            Assert.DoesNotContain("sample", doc.OuterXml);
        }

        [Fact]
        public void Encrypt_X509_XmlNull()
        {
            var certificate = TestHelpers.GetSampleX509Certificate();
            EncryptedXml exml = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => exml.Encrypt(null, certificate.Item1));
        }

        [Fact]
        public void Encrypt_X509_CertificateNull()
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            EncryptedXml exml = new EncryptedXml();
            X509Certificate certificate = null;
            Assert.Throws<ArgumentNullException>(() => exml.Encrypt(doc.DocumentElement, certificate));
        }

        [Fact]
        public void Encrypt_XmlNull()
        {
            EncryptedXml exml = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => exml.Encrypt(null, "aes"));
        }

        [Fact]
        public void Encrypt_KeyNameNull()
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            EncryptedXml exml = new EncryptedXml();
            string keyName = null;
            Assert.Throws<ArgumentNullException>(() => exml.Encrypt(doc.DocumentElement, keyName));
        }

        [Fact]
        public void Encrypt_MissingKey()
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            EncryptedXml exml = new EncryptedXml();
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => exml.Encrypt(doc.DocumentElement, "aes"));
        }

        [Fact]
        public void Encrypt_RSA()
        {
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var pair = keyGen.GenerateKeyPair();
            CheckEncryptionMethod(pair.Public, EncryptedXml.XmlEncRSA15Url);
        }

        [Fact]
        public void Encrypt_TripleDES()
        {
            var aes = CipherUtilities.GetCipher("DESEDE/CBC/PKCS7PADDING");
            var random = new SecureRandom();
            var ivdata = new byte[64 / 8];
            var keydata = new byte[192 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new DesEdeParameters(keydata), ivdata);

            CheckEncryptionMethod(param, EncryptedXml.XmlEncTripleDESKeyWrapUrl);
        }

        [Fact]
        public void Encrypt_AES128()
        {
            var aes = CipherUtilities.GetCipher("AES/CBC/PKCS7PADDING");
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[128 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            CheckEncryptionMethod(param, EncryptedXml.XmlEncAES128KeyWrapUrl);
        }

        [Fact]
        public void Encrypt_AES192()
        {
            var aes = CipherUtilities.GetCipher("AES/CBC/PKCS7PADDING");
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[192 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            CheckEncryptionMethod(param, EncryptedXml.XmlEncAES192KeyWrapUrl);
        }

        [Fact]
        public void Encrypt_NotSupportedAlgorithm()
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => CheckEncryptionMethod("", EncryptedXml.XmlEncAES192KeyWrapUrl));
        }

        [Fact]
        public void AddKeyNameMapping_KeyNameNull()
        {
            EncryptedXml exml = new EncryptedXml();

            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            Assert.Throws<ArgumentNullException>(() => exml.AddKeyNameMapping(null, param));
        }

        [Fact]
        public void AddKeyNameMapping_KeyObjectNull()
        {
            EncryptedXml exml = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => exml.AddKeyNameMapping("no_object", null));
        }

        [Fact]
        public void AddKeyNameMapping_KeyObjectWrongType()
        {
            EncryptedXml exml = new EncryptedXml();
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => exml.AddKeyNameMapping("string", ""));
        }

        [Fact]
        public void ReplaceData_XmlElementNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.ReplaceData(null, new byte[0]));
        }

        [Fact]
        public void ReplaceData_EncryptedDataNull()
        {
            EncryptedXml ex = new EncryptedXml();
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            Assert.Throws<ArgumentNullException>(() => ex.ReplaceData(doc.DocumentElement, null));
        }

        [Fact]
        public void ReplaceElement_XmlElementNull()
        {
            Assert.Throws<ArgumentNullException>(() => EncryptedXml.ReplaceElement(null, new EncryptedData(), true));
        }

        [Fact]
        public void ReplaceElement_EncryptedDataNull()
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            Assert.Throws<ArgumentNullException>(() => EncryptedXml.ReplaceElement(doc.DocumentElement, null, false));
        }

        [Fact]
        public void ReplaceElement_ContentTrue()
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            EncryptedData edata = new EncryptedData();
            edata.CipherData.CipherValue = new byte[16];
            EncryptedXml.ReplaceElement(doc.DocumentElement, edata, true);
            Assert.Equal("root", doc.DocumentElement.Name);
            Assert.Equal("EncryptedData", doc.DocumentElement.FirstChild.Name);
        }

        [Fact]
        public void GetIdElement_XmlDocumentNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Null(ex.GetIdElement(null, "value"));
        }

        [Fact]
        public void GetIdElement_StringNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.GetIdElement(new XmlDocument(), null));
        }

        [Fact]
        public void GetDecryptionKey_EncryptedDataNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.GetDecryptionKey(null, EncryptedXml.XmlEncAES128Url));
        }

        [Fact]
        public void GetDecryptionKey_NoEncryptionMethod()
        {
            EncryptedData edata = new EncryptedData();
            edata.KeyInfo = new KeyInfo();
            edata.KeyInfo.AddClause(new KeyInfoEncryptedKey(new EncryptedKey()));
            EncryptedXml exml = new EncryptedXml();
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => exml.GetDecryptionKey(edata, null));
        }

        [Fact]
        public void GetDecryptionKey_StringNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Null(ex.GetDecryptionKey(new EncryptedData(), null));
        }

        [Fact]
        public void GetDecryptionKey_KeyInfoName()
        {
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            EncryptedData edata = new EncryptedData();
            edata.KeyInfo = new KeyInfo();
            edata.KeyInfo.AddClause(new KeyInfoName("aes"));

            EncryptedXml exml = new EncryptedXml();
            exml.AddKeyNameMapping("aes", param);
            var decryptedAlg = exml.GetDecryptionKey(edata, null);

            Assert.IsType<ParametersWithIV>(decryptedAlg);
            Assert.Equal(((KeyParameter)param.Parameters).GetKey(), ((KeyParameter)((ParametersWithIV)decryptedAlg).Parameters).GetKey());
        }

        [Fact]
        public void GetDecryptionKey_CarriedKeyName()
        {
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            keydata = new byte[128 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var innerParam = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            EncryptedData edata = new EncryptedData();
            edata.KeyInfo = new KeyInfo();
            edata.KeyInfo.AddClause(new KeyInfoName("aes"));

            EncryptedKey ekey = new EncryptedKey();
            byte[] encKeyBytes = EncryptedXml.EncryptKey(((KeyParameter)innerParam.Parameters).GetKey(), (KeyParameter)param.Parameters);
            ekey.CipherData = new CipherData(encKeyBytes);
            ekey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            ekey.CarriedKeyName = "aes";
            ekey.KeyInfo = new KeyInfo();
            ekey.KeyInfo.AddClause(new KeyInfoName("another_aes"));

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(ekey.GetXml().OuterXml);

            EncryptedXml exml = new EncryptedXml(doc);
            exml.AddKeyNameMapping("another_aes", param);
            var decryptedAlg = exml.GetDecryptionKey(edata, EncryptedXml.XmlEncAES256Url);

            Assert.IsType<KeyParameter>(decryptedAlg);
            Assert.Equal(((KeyParameter)innerParam.Parameters).GetKey(), ((KeyParameter)decryptedAlg).GetKey());
        }

        [Fact]
        public void GetDecryptionIV_EncryptedDataNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.GetDecryptionIV(null, EncryptedXml.XmlEncAES128Url));
        }

        [Fact]
        public void GetDecryptionIV_StringNull()
        {
            EncryptedXml ex = new EncryptedXml();
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            encryptedData.CipherData = new CipherData(new byte[16]);
            Assert.Equal(new byte[16], ex.GetDecryptionIV(encryptedData, null));
        }

        [Fact]
        public void GetDecryptionIV_StringNullWithoutEncryptionMethod()
        {
            EncryptedXml ex = new EncryptedXml();
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.CipherData = new CipherData(new byte[16]);
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ex.GetDecryptionIV(encryptedData, null));
        }

        [Fact]
        public void GetDecryptionIV_InvalidAlgorithmUri()
        {
            EncryptedXml ex = new EncryptedXml();
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.CipherData = new CipherData(new byte[16]);
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ex.GetDecryptionIV(encryptedData, "invalid"));
        }

        [Fact]
        public void GetDecryptionIV_TripleDesUri()
        {
            EncryptedXml ex = new EncryptedXml();
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.CipherData = new CipherData(new byte[16]);
            Assert.Equal(8, ex.GetDecryptionIV(encryptedData, EncryptedXml.XmlEncTripleDESUrl).Length);
        }

        [Fact]
        public void DecryptKey_KeyNull()
        {
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            Assert.Throws<ArgumentNullException>(() => EncryptedXml.DecryptKey(null, new KeyParameter(keydata)));
        }

        [Fact]
        public void DecryptKey_SymmetricAlgorithmNull()
        {
            Assert.Throws<ArgumentNullException>(() => EncryptedXml.DecryptKey(new byte[16], null));
        }

        [Fact]
        public void EncryptKey_KeyNull()
        {
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            Assert.Throws<ArgumentNullException>(() => EncryptedXml.EncryptKey(null, new KeyParameter(keydata)));
        }

        [Fact]
        public void EncryptKey_SymmetricAlgorithmNull()
        {
            Assert.Throws<ArgumentNullException>(() => EncryptedXml.EncryptKey(new byte[16], null));
        }

        /*
        [Fact]
        public void EncryptKey_WrongSymmetricAlgorithm()
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.EncryptKey(new byte[16], new NotSupportedSymmetricAlgorithm()));
        }
        */

        [Fact]
        public void EncryptKey_RSA_KeyDataNull()
        {
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var pair = keyGen.GenerateKeyPair();

            Assert.Throws<ArgumentNullException>(() => EncryptedXml.EncryptKey(null, (RsaKeyParameters)pair.Public, false));
        }

        [Fact]
        public void EncryptKey_RSA_RSANull()
        {
            Assert.Throws<ArgumentNullException>(() => EncryptedXml.EncryptKey(new byte[16], null, false));
        }

        [Fact]
        public void EncryptKey_RSA_UseOAEP()
        {
            byte[] data = Encoding.ASCII.GetBytes("12345678");
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var pair = keyGen.GenerateKeyPair();

            byte[] encryptedData = EncryptedXml.EncryptKey(data, (RsaKeyParameters)pair.Public, true);
            byte[] decryptedData = EncryptedXml.DecryptKey(encryptedData, (RsaKeyParameters)pair.Private, true);
            Assert.Equal(data, decryptedData);
        }

        [Fact]
        public void DecryptData_EncryptedDataNull()
        {
            EncryptedXml ex = new EncryptedXml();
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            Assert.Throws<ArgumentNullException>(() => ex.DecryptData(null, param));
        }

        [Fact]
        public void DecryptData_SymmetricAlgorithmNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.DecryptData(new EncryptedData(), null));
        }

        [Fact]
        public void DecryptData_CipherReference_InvalidUri()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string xml = "<root>  <child>sample</child>   </root>";
            doc.LoadXml(xml);

            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            EncryptedXml exml = new EncryptedXml();
            exml.AddKeyNameMapping("aes", param);
            EncryptedData ed = exml.Encrypt(doc.DocumentElement, "aes");
            ed.CipherData = new CipherData();
            ed.CipherData.CipherReference = new CipherReference("invaliduri");

            // https://github.com/dotnet/corefx/issues/19272
            Action decrypt = () => exml.DecryptData(ed, param);
            Assert.Throws<System.Security.Cryptography.CryptographicException>(decrypt);
        }

        [Fact]
        public void DecryptData_CipherReference_IdUri()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string xml = "<root>  <child>sample</child>   </root>";
            doc.LoadXml(xml);

            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            EncryptedXml exml = new EncryptedXml(doc);
            string cipherValue = Convert.ToBase64String(exml.EncryptData(Encoding.UTF8.GetBytes(xml), param));

            EncryptedData ed = new EncryptedData();
            ed.Type = EncryptedXml.XmlEncElementUrl;
            ed.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            ed.CipherData = new CipherData();
            // Create CipherReference: first extract node value, then convert from base64 using Transforms
            ed.CipherData.CipherReference = new CipherReference("#ID_0");
            string xslt = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match = \"/\"><xsl:value-of select=\".\" /></xsl:template></xsl:stylesheet>";
            XmlDsigXsltTransform xsltTransform = new XmlDsigXsltTransform();
            XmlDocument xsltDoc = new XmlDocument();
            xsltDoc.LoadXml(xslt);
            xsltTransform.LoadInnerXml(xsltDoc.ChildNodes);
            ed.CipherData.CipherReference.AddTransform(xsltTransform);
            ed.CipherData.CipherReference.AddTransform(new XmlDsigBase64Transform());

            // Create a document with EncryptedData and node with the actual cipher data (with the ID)
            doc.LoadXml("<root></root>");
            XmlNode encryptedDataNode = doc.ImportNode(ed.GetXml(), true);
            doc.DocumentElement.AppendChild(encryptedDataNode);
            XmlElement cipherDataByReference = doc.CreateElement("CipherData");
            cipherDataByReference.SetAttribute("ID", "ID_0");
            cipherDataByReference.InnerText = cipherValue;
            doc.DocumentElement.AppendChild(cipherDataByReference);

            string decryptedXmlString = Encoding.UTF8.GetString(exml.DecryptData(ed, param));
            Assert.Equal(xml, decryptedXmlString);
        }

        [Fact]
        public void EncryptData_DataNull()
        {
            EncryptedXml ex = new EncryptedXml();

            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            Assert.Throws<ArgumentNullException>(() => ex.EncryptData(null, param));
        }

        [Fact]
        public void EncryptData_SymmetricAlgorithmNull()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.EncryptData(new byte[16], null));
        }

        [Fact]
        public void EncryptData_Xml_SymmetricAlgorithmNull()
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.EncryptData(doc.DocumentElement, null, true));
        }

        [Fact]
        public void EncryptData_Xml_XmlElementNull()
        {
            EncryptedXml ex = new EncryptedXml();
            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            Assert.Throws<ArgumentNullException>(() => ex.EncryptData(null, param, true));
        }

        [Fact]
        public void DecryptEncryptedKey_Null()
        {
            EncryptedXml ex = new EncryptedXml();
            Assert.Throws<ArgumentNullException>(() => ex.DecryptEncryptedKey(null));
        }

        [Fact]
        public void DecryptEncryptedKey_Empty()
        {
            EncryptedXml ex = new EncryptedXml();
            EncryptedKey ek = new EncryptedKey();
            Assert.Null(ex.DecryptEncryptedKey(ek));
        }

        [Fact]
        public void DecryptEncryptedKey_KeyInfoRetrievalMethod()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string xml = "<root>  <child>sample</child>   </root>";
            doc.LoadXml(xml);

            var random = new SecureRandom();
            var ivdata = new byte[128 / 8];
            var keydata = new byte[256 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var param = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            keydata = new byte[128 / 8];
            random.NextBytes(ivdata);
            random.NextBytes(keydata);
            var innerParam = new ParametersWithIV(new KeyParameter(keydata), ivdata);

            EncryptedXml exml = new EncryptedXml(doc);
            exml.AddKeyNameMapping("aes", param);

            EncryptedKey ekey = new EncryptedKey();
            byte[] encKeyBytes = EncryptedXml.EncryptKey(((KeyParameter)innerParam.Parameters).GetKey(), (KeyParameter)param.Parameters);
            ekey.CipherData = new CipherData(encKeyBytes);
            ekey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            ekey.Id = "Key_ID";
            ekey.KeyInfo = new KeyInfo();
            ekey.KeyInfo.AddClause(new KeyInfoName("aes"));

            doc.LoadXml(ekey.GetXml().OuterXml);

            EncryptedKey ekeyRetrieval = new EncryptedKey();
            KeyInfo keyInfoRetrieval = new KeyInfo();
            keyInfoRetrieval.AddClause(new KeyInfoRetrievalMethod("#Key_ID"));
            ekeyRetrieval.KeyInfo = keyInfoRetrieval;

            byte[] decryptedKey = exml.DecryptEncryptedKey(ekeyRetrieval);
            Assert.Equal(((KeyParameter)innerParam.Parameters).GetKey(), decryptedKey);

            EncryptedData eData = new EncryptedData();
            eData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            eData.KeyInfo = keyInfoRetrieval;
            var decryptedAlg = exml.GetDecryptionKey(eData, null);
            Assert.Equal(((KeyParameter)innerParam.Parameters).GetKey(), ((KeyParameter)decryptedAlg).GetKey());
        }

        [Fact]
        public void DecryptEncryptedKey_KeyInfoEncryptedKey()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            string xml = "<root>  <child>sample</child>   </root>";
            doc.LoadXml(xml);

            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            keydata = new byte[128 / 8];
            random.NextBytes(keydata);
            var innerParam = new KeyParameter(keydata);

            keydata = new byte[192 / 8];
            random.NextBytes(keydata);
            var outerParam = new KeyParameter(keydata);

            EncryptedXml exml = new EncryptedXml(doc);
            exml.AddKeyNameMapping("aes", param);

            EncryptedKey ekey = new EncryptedKey();
            byte[] encKeyBytes = EncryptedXml.EncryptKey(outerParam.GetKey(), param);
            ekey.CipherData = new CipherData(encKeyBytes);
            ekey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            ekey.Id = "Key_ID";
            ekey.KeyInfo = new KeyInfo();
            ekey.KeyInfo.AddClause(new KeyInfoName("aes"));

            KeyInfo topLevelKeyInfo = new KeyInfo();
            topLevelKeyInfo.AddClause(new KeyInfoEncryptedKey(ekey));

            EncryptedKey ekeyTopLevel = new EncryptedKey();
            byte[] encTopKeyBytes = EncryptedXml.EncryptKey(innerParam.GetKey(), outerParam);
            ekeyTopLevel.CipherData = new CipherData(encTopKeyBytes);
            ekeyTopLevel.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            ekeyTopLevel.KeyInfo = topLevelKeyInfo;

            doc.LoadXml(ekeyTopLevel.GetXml().OuterXml);

            byte[] decryptedKey = exml.DecryptEncryptedKey(ekeyTopLevel);
            Assert.Equal(innerParam.GetKey(), decryptedKey);

            EncryptedData eData = new EncryptedData();
            eData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
            eData.KeyInfo = topLevelKeyInfo;
            var decryptedAlg = exml.GetDecryptionKey(eData, null);
            Assert.Equal(outerParam.GetKey(), ((KeyParameter)decryptedAlg).GetKey());
        }

        [Fact]
        public void EncryptKey_TripleDES()
        {
            var random = new SecureRandom();
            var keydata = new byte[192 / 8];
            random.NextBytes(keydata);
            var param = new DesEdeParameters(keydata);

            byte[] key = Encoding.ASCII.GetBytes("123456781234567812345678");

            byte[] encryptedKey = EncryptedXml.EncryptKey(key, param);

            Assert.NotNull(encryptedKey);
            Assert.Equal(key, EncryptedXml.DecryptKey(encryptedKey, param));
        }

        [Fact]
        public void EncryptKey_AES()
        {
            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            byte[] key = Encoding.ASCII.GetBytes("123456781234567812345678");

            byte[] encryptedKey = EncryptedXml.EncryptKey(key, param);

            Assert.NotNull(encryptedKey);
            Assert.Equal(key, EncryptedXml.DecryptKey(encryptedKey, param));
        }

        [Fact]
        public void EncryptKey_AES8Bytes()
        {
            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            byte[] key = Encoding.ASCII.GetBytes("12345678");

            byte[] encryptedKey = EncryptedXml.EncryptKey(key, param);

            Assert.NotNull(encryptedKey);
            Assert.Equal(key, EncryptedXml.DecryptKey(encryptedKey, param));
        }

        [Fact]
        public void EncryptKey_AESNotDivisibleBy8()
        {
            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            byte[] key = Encoding.ASCII.GetBytes("1234567");

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.EncryptKey(key, param));
        }

        [Fact]
        public void DecryptKey_TripleDESWrongKeySize()
        {
            var random = new SecureRandom();
            var keydata = new byte[192 / 8];
            random.NextBytes(keydata);
            var param = new DesEdeParameters(keydata);

            byte[] key = Encoding.ASCII.GetBytes("123");

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.DecryptKey(key, param));
        }

        [Fact]
        public void DecryptKey_TripleDESCorruptedKey()
        {
            var random = new SecureRandom();
            var keydata = new byte[192 / 8];
            random.NextBytes(keydata);
            var param = new DesEdeParameters(keydata);

            byte[] key = Encoding.ASCII.GetBytes("123456781234567812345678");

            byte[] encryptedKey = EncryptedXml.EncryptKey(key, param);
            encryptedKey[0] ^= 0xFF;

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.DecryptKey(encryptedKey, param));
        }

        [Fact]
        public void DecryptKey_AESWrongKeySize()
        {
            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            byte[] key = Encoding.ASCII.GetBytes("123");

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.DecryptKey(key, param));
        }

        [Fact]
        public void DecryptKey_AESCorruptedKey()
        {
            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            byte[] key = Encoding.ASCII.GetBytes("123456781234567812345678");

            byte[] encryptedKey = EncryptedXml.EncryptKey(key, param);
            encryptedKey[0] ^= 0xFF;

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.DecryptKey(encryptedKey, param));
        }

        [Fact]
        public void DecryptKey_AESCorruptedKey8Bytes()
        {
            var random = new SecureRandom();
            var keydata = new byte[256 / 8];
            random.NextBytes(keydata);
            var param = new KeyParameter(keydata);

            byte[] key = Encoding.ASCII.GetBytes("12345678");

            byte[] encryptedKey = EncryptedXml.EncryptKey(key, param);
            encryptedKey[0] ^= 0xFF;

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.DecryptKey(encryptedKey, param));
        }

        /*
        [Fact]
        public void DecryptKey_NotSupportedAlgorithm()
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => EncryptedXml.DecryptKey(new byte[16], new NotSupportedSymmetricAlgorithm()));
        }
        */

        [Fact]
        public void DecryptKey_RSA_KeyDataNull()
        {
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var pair = keyGen.GenerateKeyPair();

            Assert.Throws<ArgumentNullException>(() => EncryptedXml.DecryptKey(null, (RsaKeyParameters)pair.Private, false));
        }

        [Fact]
        public void DecryptKey_RSA_RSANull()
        {
            Assert.Throws<ArgumentNullException>(() => EncryptedXml.DecryptKey(new byte[16], null, false));
        }

        [Fact]
        public void Properties()
        {
            EncryptedXml exml = new EncryptedXml();
            exml.XmlDSigSearchDepth = 10;
            exml.Resolver = null;
            exml.Padding = "NOPADDING";
            exml.Mode = "CBC";
            exml.Encoding = Encoding.ASCII;
            exml.Recipient = "Recipient";

            Assert.Equal(10, exml.XmlDSigSearchDepth);
            Assert.Null(exml.Resolver);
            Assert.Equal("NOPADDING", exml.Padding);
            Assert.Equal("CBC", exml.Mode);
            Assert.Equal(Encoding.ASCII, exml.Encoding);
            Assert.Equal("Recipient", exml.Recipient);
        }

        private void CheckEncryptionMethod(object algorithm, string uri)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<root />");
            EncryptedXml exml = new EncryptedXml();
            exml.AddKeyNameMapping("key", algorithm);

            EncryptedData edata = exml.Encrypt(doc.DocumentElement, "key");
            IEnumerator keyInfoEnum = edata.KeyInfo.GetEnumerator();
            keyInfoEnum.MoveNext();
            KeyInfoEncryptedKey kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;

            Assert.NotNull(edata);
            Assert.Equal(uri, kiEncKey.EncryptedKey.EncryptionMethod.KeyAlgorithm);
            Assert.NotNull(edata.CipherData.CipherValue);
        }
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Org.BouncyCastle.Crypto.Xml.Tests
{
    public class XmlLicenseEncryptedRef : IRelDecryptor
    {
        List<AsymmetricCipherKeyPair> _asymmetricKeys = new List<AsymmetricCipherKeyPair>();

        public XmlLicenseEncryptedRef()
        {
        }

        public void AddAsymmetricKey(AsymmetricCipherKeyPair key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _asymmetricKeys.Add(key);
        }

        private static bool PublicKeysEqual(RsaKeyParameters a, RsaKeyParameters b)
        {
            return a.Exponent.Equals(b.Exponent) && a.Modulus.Equals(b.Modulus);
        }

        public Stream Decrypt(EncryptionMethod encryptionMethod, KeyInfo keyInfo, Stream toDecrypt)
        {
            Assert.NotNull(encryptionMethod);
            Assert.NotNull(keyInfo);
            Assert.NotNull(toDecrypt);
            Assert.True(encryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncAES128Url
                     || encryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncAES192Url
                     || encryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncAES256Url);

            Assert.Equal(keyInfo.Count, 1);

            byte[] decryptedKey = null;

            foreach (KeyInfoClause clause in keyInfo)
            {
                if (clause is KeyInfoEncryptedKey)
                {
                    KeyInfoEncryptedKey encryptedKeyInfo = clause as KeyInfoEncryptedKey;
                    EncryptedKey encryptedKey = encryptedKeyInfo.EncryptedKey;

                    Assert.Equal(encryptedKey.EncryptionMethod.KeyAlgorithm, EncryptedXml.XmlEncRSAOAEPUrl);
                    Assert.Equal(encryptedKey.KeyInfo.Count, 1);
                    Assert.NotEqual(_asymmetricKeys.Count, 0);

                    RsaKeyParameters rsaParams = null;
                    RsaKeyParameters rsaInputParams = null;

                    foreach (KeyInfoClause rsa in encryptedKey.KeyInfo)
                    {
                        if (rsa is RSAKeyValue)
                        {
                            rsaParams = (rsa as RSAKeyValue).Key;
                            break;
                        }
                        else
                        {
                            Assert.True(false, "Invalid License - MalformedKeyInfoClause");
                        }
                    }

                    bool keyMismatch = true;
                    foreach (AsymmetricCipherKeyPair key in _asymmetricKeys)
                    {
                        RsaKeyParameters rsaKey = key.Private as RsaKeyParameters;
                        Assert.NotNull(rsaKey);

                        rsaInputParams = key.Public as RsaKeyParameters;
                        Assert.NotNull(rsaInputParams);

                        if (!PublicKeysEqual(rsaParams, rsaInputParams))
                        {
                            continue;
                        }

                        keyMismatch = false;

                        // Decrypt session key
                        byte[] encryptedKeyValue = encryptedKey.CipherData.CipherValue;

                        if (encryptedKeyValue == null)
                            throw new System.Security.Cryptography.CryptographicException("MissingKeyCipher");

                        decryptedKey = EncryptedXml.DecryptKey(encryptedKeyValue,
                                                                     rsaKey, true);
                        break;
                    }

                    if (keyMismatch)
                    {
                        throw new Exception("Invalid License - AsymmetricKeyMismatch");
                    }
                }
                else if (clause is KeyInfoName)
                {
                    Assert.True(false, "This test should not have KeyInfoName clauses");
                }
                else
                {
                    throw new System.Security.Cryptography.CryptographicException("MalformedKeyInfoClause");
                }

                break;
            }

            if (decryptedKey == null)
            {
                throw new System.Security.Cryptography.CryptographicException("KeyDecryptionFailure");
            }

            return DecryptStream(toDecrypt, new KeyParameter(decryptedKey), "AES/CBC/PKCS7");
        }

        private static Stream DecryptStream(Stream toDecrypt, KeyParameter key, string algId)
        {
            Assert.NotNull(key);

            var decryptor = CipherUtilities.GetCipher(algId);

            byte[] IV = new byte[decryptor.GetBlockSize()];

            // Get the IV from the encrypted content.
            toDecrypt.Read(IV, 0, IV.Length);
            byte[] encryptedContentValue = new byte[toDecrypt.Length - IV.Length];

            // Get the encrypted content following the IV.
            toDecrypt.Read(encryptedContentValue, 0, encryptedContentValue.Length);

            byte[] decryptedContent;

            decryptor.Init(false, new ParametersWithIV(key, IV));
            decryptedContent = decryptor.DoFinal(encryptedContentValue);

            return new MemoryStream(decryptedContent);
        }

        public static void Encrypt(Stream toEncrypt, RsaKeyParameters key, out KeyInfo keyInfo, out EncryptionMethod encryptionMethod, out CipherData cipherData)
        {
            var random = new SecureRandom();
            var keyData = new byte[128 / 8];
            var ivData = new byte[128 / 8];
            random.NextBytes(ivData);
            random.NextBytes(keyData);
            var sessionKey = new ParametersWithIV(new KeyParameter(keyData), ivData);

            encryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES128Url);
            keyInfo = new KeyInfo();

            EncryptedKey encKey;
            keyInfo.AddClause(
                new KeyInfoEncryptedKey(
                    encKey = new EncryptedKey()
                    {
                        CipherData = new CipherData(EncryptedXml.EncryptKey(keyData, key, useOAEP: true)),
                        EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl)
                    }));

            encKey.KeyInfo.AddClause(new RSAKeyValue(key));

            byte[] dataToEncrypt = new byte[toEncrypt.Length];
            toEncrypt.Read(dataToEncrypt, 0, (int)toEncrypt.Length);

            var encryptedXml = new EncryptedXml();
            encryptedXml.Padding = "PKCS7";
            encryptedXml.Mode = "CBC";
            byte[] encryptedData = encryptedXml.EncryptData(dataToEncrypt, sessionKey);
            cipherData = new CipherData(encryptedData);
        }

        [Fact]
        public static void ItRoundTrips()
        {
            byte[] input = new byte[] { 1, 2, 7, 4 };
            MemoryStream ms = new MemoryStream(input);
            KeyInfo keyInfo;
            EncryptionMethod encMethod;
            CipherData cipherData;
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var pair = keyGen.GenerateKeyPair();
            Encrypt(ms, (RsaKeyParameters)pair.Public, out keyInfo, out encMethod, out cipherData);

            XmlLicenseEncryptedRef decr = new XmlLicenseEncryptedRef();
            decr.AddAsymmetricKey(pair);
            using (var encrypted = new MemoryStream(cipherData.CipherValue))
            using (Stream decrypted = decr.Decrypt(encMethod, keyInfo, encrypted))
            {
                byte[] decryptedBytes = new byte[decrypted.Length];
                decrypted.Read(decryptedBytes, 0, (int)decrypted.Length);
                Assert.Equal(input, decryptedBytes);
            }
        }
    }
}

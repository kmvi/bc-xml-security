// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal static class CryptoHelpers
    {
        private static readonly char[] _invalidChars = new char[] { ',', '`', '[', '*', '&' };

        [SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 needed for compat.")]
        [SuppressMessage("Microsoft.Security", "CA5351", Justification = "HMACMD5 needed for compat.")]
        public static object CreateFromKnownName(string name)
        {
            switch (name)
            {
                case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315":
                    return new XmlDsigC14NTransform();
                case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
                    return new XmlDsigC14NWithCommentsTransform();
                case "http://www.w3.org/2001/10/xml-exc-c14n#":
                    return new XmlDsigExcC14NTransform();
                case "http://www.w3.org/2001/10/xml-exc-c14n#WithComments":
                    return new XmlDsigExcC14NWithCommentsTransform();
                case "http://www.w3.org/2000/09/xmldsig#base64":
                    return new XmlDsigBase64Transform();
                case "http://www.w3.org/TR/1999/REC-xpath-19991116":
                    return new XmlDsigXPathTransform();
                case "http://www.w3.org/TR/1999/REC-xslt-19991116":
                    return new XmlDsigXsltTransform();
                case "http://www.w3.org/2000/09/xmldsig#enveloped-signature":
                    return new XmlDsigEnvelopedSignatureTransform();
                case "http://www.w3.org/2002/07/decrypt#XML":
                    return new XmlDecryptionTransform();
                case "urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform":
                    return new XmlLicenseTransform();
                case "http://www.w3.org/2000/09/xmldsig# X509Data":
                    return new KeyInfoX509Data();
                case "http://www.w3.org/2000/09/xmldsig# KeyName":
                    return new KeyInfoName();
                case "http://www.w3.org/2000/09/xmldsig# KeyValue/DSAKeyValue":
                    return new DSAKeyValue();
                case "http://www.w3.org/2000/09/xmldsig# KeyValue/RSAKeyValue":
                    return new RSAKeyValue();
                case "http://www.w3.org/2000/09/xmldsig# RetrievalMethod":
                    return new KeyInfoRetrievalMethod();
                case "http://www.w3.org/2001/04/xmlenc# EncryptedKey":
                    return new KeyInfoEncryptedKey();
                case "http://www.w3.org/2000/09/xmldsig#dsa-sha1":
                case "System.Security.Cryptography.DSASignatureDescription":
                    //return SignerUtilities.GetSigner("DSAWITHSHA1");
                    return new DsaDigestSigner2(new DsaSigner(), new Sha1Digest());
                case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                case "System.Security.Cryptography.RSASignatureDescription":
                    return SignerUtilities.GetSigner("SHA1WITHRSA");
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                    return SignerUtilities.GetSigner("SHA256WITHRSA");
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                    return SignerUtilities.GetSigner("SHA384WITHRSA");
                case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                    return SignerUtilities.GetSigner("SHA512WITHRSA");
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411":
                case "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411":
                    return SignerUtilities.GetSigner("GOST3411WITHECGOST3410");
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012256":
                    return new Gost3410DigestSigner(new ECGost3410Signer(), new Gost3411_2012_256Digest());
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012512":
                    return new Gost3410DigestSigner(new ECGost3410Signer(), new Gost3411_2012_512Digest());

                // workarounds for issue https://github.com/dotnet/corefx/issues/16563
                // remove attribute from this method when removing them
                case "http://www.w3.org/2000/09/xmldsig#sha1":
                    return DigestUtilities.GetDigest("SHA-1");
                case "http://www.w3.org/2001/04/xmlenc#sha256":
                    return DigestUtilities.GetDigest("SHA-256");
                case "http://www.w3.org/2001/04/xmldsig-more#sha384":
                    return DigestUtilities.GetDigest("SHA-384");
                case "http://www.w3.org/2001/04/xmlenc#sha512":
                    return DigestUtilities.GetDigest("SHA-512");
                case "http://www.w3.org/2001/04/xmlenc#ripemd160":
                    return DigestUtilities.GetDigest("RIPEMD-160");
                case "MD5":
                    return DigestUtilities.GetDigest("MD5");
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411":
                case "http://www.w3.org/2001/04/xmldsig-more#gostr3411":
                    return DigestUtilities.GetDigest("GOST3411");
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256":
                    return DigestUtilities.GetDigest("GOST3411-2012-256");
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512":
                    return DigestUtilities.GetDigest("GOST3411-2012-512");
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-md5":
                    return MacUtilities.GetMac("HMAC-MD5");
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256":
                    return MacUtilities.GetMac("HMAC-SHA256");
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384":
                    return MacUtilities.GetMac("HMAC-SHA384");
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512":
                    return MacUtilities.GetMac("HMAC-SHA512");
                case "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160":
                    return MacUtilities.GetMac("HMAC-RIPEMD160");
                case "http://www.w3.org/2001/04/xmlenc#des-cbc":
                    return CipherUtilities.GetCipher("DES/CBC/PKCS7Padding");
                case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
                    return CipherUtilities.GetCipher("DESede/CBC/PKCS7Padding");
                case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                case "http://www.w3.org/2001/04/xmlenc#kw-aes128":
                    return new PaddedBufferedBlockCipher(new CbcBlockCipher(new RijndaelEngine(128)), new Pkcs7Padding());
                case "http://www.w3.org/2001/04/xmlenc#aes192-cbc":
                case "http://www.w3.org/2001/04/xmlenc#kw-aes192":
                    return new PaddedBufferedBlockCipher(new CbcBlockCipher(new RijndaelEngine(192)), new Pkcs7Padding());
                case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                case "http://www.w3.org/2001/04/xmlenc#kw-aes256":
                    return new PaddedBufferedBlockCipher(new CbcBlockCipher(new RijndaelEngine(256)), new Pkcs7Padding());
            }

            return null;
        }

        public static T CreateFromName<T>(string name) where T : class
        {
            if (name == null || name.IndexOfAny(_invalidChars) >= 0) {
                return null;
            }
            try {
                return CreateFromKnownName(name) as T;
            } catch (Exception) {
                return null;
            }
        }
    }
}

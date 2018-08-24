// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal static class CryptoHelpers
    {
        [SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 needed for compat.")]
        [SuppressMessage("Microsoft.Security", "CA5351", Justification = "HMACMD5 needed for compat.")]
        public static object CreateFromName(string name)
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
                //case "http://www.w3.org/2002/07/decrypt#XML":
                //    return new XmlDecryptionTransform();
                //case "urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform":
                //    return new XmlLicenseTransform();
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
                //case "http://www.w3.org/2001/04/xmlenc# EncryptedKey":
                //    return new KeyInfoEncryptedKey();
                case "http://www.w3.org/2000/09/xmldsig#dsa-sha1":
                case "System.Security.Cryptography.DSASignatureDescription":
                    return SignerUtilities.GetSigner("DSAWITHSHA1");
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
                    return new Gost3410DigestSigner(new ECGost3410Signer(), new GOST3411_2012_256Digest());
                case "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012512":
                    return new Gost3410DigestSigner(new ECGost3410Signer(), new GOST3411_2012_512Digest());

                // workarounds for issue https://github.com/dotnet/corefx/issues/16563
                // remove attribute from this method when removing them
                case "http://www.w3.org/2000/09/xmldsig#sha1":
                    return DigestUtilities.GetDigest("SHA-1");
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
                case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
                    return CipherUtilities.GetCipher("DESede/CBC/PKCS7Padding");
            }

            throw new NotSupportedException(name);
        }
    }
}

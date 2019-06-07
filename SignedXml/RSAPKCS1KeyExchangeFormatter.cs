// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class RSAPKCS1KeyExchangeFormatter
    {
        private RsaKeyParameters _rsaKey;
        private SecureRandom RngValue;

        public RSAPKCS1KeyExchangeFormatter() { }

        public RSAPKCS1KeyExchangeFormatter(RsaKeyParameters key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _rsaKey = key;
        }

        public string Parameters
        {
            get
            {
                return "<enc:KeyEncryptionMethod enc:Algorithm=\"http://www.microsoft.com/xml/security/algorithm/PKCS1-v1.5-KeyEx\" xmlns:enc=\"http://www.microsoft.com/xml/security/encryption/v1.0\" />";
            }
        }

        public SecureRandom Rng {
            get { return RngValue; }
            set { RngValue = value; }
        }

        public void SetKey(RsaKeyParameters key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _rsaKey = key;
        }

        public byte[] CreateKeyExchange(byte[] rgbData, Type symAlgType)
        {
            return CreateKeyExchange(rgbData);
        }

        public byte[] CreateKeyExchange(byte[] rgbData)
        {
            if (_rsaKey == null)
                throw new System.Security.Cryptography.CryptographicUnexpectedOperationException(SR.Cryptography_MissingKey);

            var rsa = CipherUtilities.GetCipher("RSA//PKCS1PADDING");
            rsa.Init(true, _rsaKey);

            return rsa.DoFinal(rgbData);
        }
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class RSAOAEPKeyExchangeDeformatter
    {
        private RsaKeyParameters _rsaKey;

        public RSAOAEPKeyExchangeDeformatter() { }
        public RSAOAEPKeyExchangeDeformatter(RsaKeyParameters key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _rsaKey = key;
        }

        public string Parameters
        {
            get {return null;}
            set { }
        }

        public byte[] DecryptKeyExchange(byte[] rgbData)
        {
            if (_rsaKey == null)
                throw new System.Security.Cryptography.CryptographicUnexpectedOperationException(SR.Cryptography_MissingKey);

            var rsa = CipherUtilities.GetCipher("RSA//OAEPPADDING");
            rsa.Init(false, _rsaKey);

            return rsa.DoFinal(rgbData);
        }

        public void SetKey(RsaKeyParameters key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _rsaKey = key;
        }
    }
}

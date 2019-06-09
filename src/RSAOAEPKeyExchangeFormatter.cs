// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class RSAOAEPKeyExchangeFormatter
    {
        private byte[] ParameterValue;
        private RsaKeyParameters _rsaKey;
        private SecureRandom RngValue;

        public RSAOAEPKeyExchangeFormatter() { }
        public RSAOAEPKeyExchangeFormatter(RsaKeyParameters key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _rsaKey = key;
        }

        public byte[] Parameter
        {
            get
            {
                if (ParameterValue != null)
                {
                    return (byte[])ParameterValue.Clone();
                }

                return null;
            }
            set
            {
                if (value != null)
                {
                    ParameterValue = (byte[])value.Clone();
                }
                else
                {
                    ParameterValue = null;
                }
            }
        }

        public string Parameters
        {
            get {return null;}
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

            var rsa = CipherUtilities.GetCipher("RSA//OAEPPADDING");
            rsa.Init(true, _rsaKey);

            return rsa.DoFinal(rgbData);
        }
    }
}

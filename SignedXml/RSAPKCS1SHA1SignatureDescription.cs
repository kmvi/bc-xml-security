// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class RSAPKCS1SHA1SignatureDescription : RSAPKCS1SignatureDescription
    {
        public RSAPKCS1SHA1SignatureDescription() : base("SHA-1")
        {
        }

        [SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 needed for compat.")]
        public sealed override HashAlgorithm CreateDigest()
        {
            throw new NotImplementedException();
            //return new Digests.DigestWrapper(DigestUtilities.GetDigest("SHA-1"));
        }
    }
}

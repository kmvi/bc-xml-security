using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class DsaDigestSigner2 : DsaDigestSigner
    {
        public DsaDigestSigner2(IDsa dsa, IDigest digest)
            : base(dsa, digest)
        {
        }

        public override bool VerifySignature(byte[] signature)
        {
            int sz = signature.Length / 2;
            var r = new BigInteger(1, signature, 0, sz);
            var s = new BigInteger(1, signature, sz, sz);
            var seq = new DerSequence(new DerInteger(r), new DerInteger(s));
            return base.VerifySignature(seq.GetDerEncoded());
        }

        public override byte[] GenerateSignature()
        {
            var result = base.GenerateSignature();
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(result);
            var r = ((DerInteger)seq[0]).Value;
            var s = ((DerInteger)seq[1]).Value;
            return r.ToByteArrayUnsigned().Concat(s.ToByteArrayUnsigned()).ToArray();
        }
    }
}

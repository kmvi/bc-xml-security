using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Org.BouncyCastle.Crypto.Xml
{
    public interface IHash
    {
        void Reset();
        void BlockUpdate(byte[] input, int inOff, int length);
        int GetHashSize();
        int DoFinal(byte[] output, int outOff);
    }

    public class SignerHashWrapper : IHash
    {
        private readonly ISigner _hash;

        public SignerHashWrapper(ISigner signer)
        {
            _hash = signer;
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            _hash.BlockUpdate(input, inOff, length);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            throw new NotSupportedException();
        }

        public int GetHashSize()
        {
            throw new NotSupportedException();
        }

        public void Reset()
        {
            _hash.Reset();
        }
    }

    public class MacHashWrapper : IHash
    {
        private readonly IMac _hash;

        public MacHashWrapper(IMac mac)
        {
            _hash = mac;
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            _hash.BlockUpdate(input, inOff, length);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            return _hash.DoFinal(output, outOff);
        }

        public int GetHashSize()
        {
            return _hash.GetMacSize();
        }

        public void Reset()
        {
            _hash.Reset();
        }
    }

    public class DigestHashWrapper : IHash
    {
        private readonly IDigest _hash;

        public DigestHashWrapper(IDigest digest)
        {
            _hash = digest;
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            _hash.BlockUpdate(input, inOff, length);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            return _hash.DoFinal(output, outOff);
        }

        public int GetHashSize()
        {
            return _hash.GetDigestSize();
        }

        public void Reset()
        {
            _hash.Reset();
        }
    }
}

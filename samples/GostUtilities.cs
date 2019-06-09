using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace _SignedXml.Samples
{
    class GostUtilities
    {
        class GostSignatureFactory : ISignatureFactory
        {
            private readonly AlgorithmIdentifier algID;
            private readonly string algorithm;
            private readonly AsymmetricKeyParameter privateKey;
            private readonly SecureRandom random;

            public GostSignatureFactory(string algorithm, AsymmetricKeyParameter privateKey)
                : this(algorithm, privateKey, null)
            {

            }

            public GostSignatureFactory(string algorithm, AsymmetricKeyParameter privateKey, SecureRandom random)
            {
                if (algorithm == null)
                    throw new ArgumentNullException("algorithm");
                if (privateKey == null)
                    throw new ArgumentNullException("privateKey");
                if (!privateKey.IsPrivate)
                    throw new ArgumentException("Key for signing must be private", "privateKey");

                this.algorithm = algorithm;
                this.privateKey = privateKey;
                this.random = random;
                this.algID = new AlgorithmIdentifier(new DerObjectIdentifier(algorithm));
            }

            public Object AlgorithmDetails
            {
                get { return this.algID; }
            }

            public IStreamCalculator CreateCalculator()
            {
                ISigner signer;
                if (algID.Algorithm.Equals(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256))
                    signer = new Gost3410DigestSigner(new ECGost3410Signer(), new Gost3411_2012_256Digest());
                else if (algID.Algorithm.Equals(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512))
                    signer = new Gost3410DigestSigner(new ECGost3410Signer(), new Gost3411_2012_512Digest());
                else if (algID.Algorithm.Equals(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001))
                    signer = new Gost3410DigestSigner(new ECGost3410Signer(), new Gost3411Digest());
                else if (algID.Algorithm.Equals(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94))
                    signer = new Gost3410DigestSigner(new Gost3410Signer(), new Gost3411Digest());
                else
                    throw new SecurityUtilityException("Signer " + algorithm + " not recognised.");

                signer.Init(true, ParameterUtilities.WithRandom(privateKey, random));

                return new DefaultSignatureCalculator(signer);
            }
        }

        private static readonly SecureRandom _random = new SecureRandom();

        public static AsymmetricCipherKeyPair GenerateGostKeyPair(DerObjectIdentifier publicKeyParamSetOid, DerObjectIdentifier digestParamSetOid)
        {
            var curve = ECGost3410NamedCurves.GetByOid(publicKeyParamSetOid);
            var ecp = new ECNamedDomainParameters(publicKeyParamSetOid, curve);
            var gostParams = new ECGost3410Parameters(ecp, publicKeyParamSetOid, digestParamSetOid, null);
            var param = new ECKeyGenerationParameters(gostParams, _random);
            var generator = new ECKeyPairGenerator();
            generator.Init(param);
            return generator.GenerateKeyPair();
        }

        public static X509Certificate GenerateSelfSignedCertificate(out AsymmetricKeyParameter privateKey)
        {
            var keypair = GenerateGostKeyPair(
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

            var generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(new BigInteger(16 * 8, _random));
            generator.SetIssuerDN(new X509Name("CN=Fake CA"));
            generator.SetSubjectDN(new X509Name("CN=Fake Subject"));
            generator.SetNotBefore(DateTime.Today.AddDays(-1));
            generator.SetNotAfter(DateTime.Today.AddYears(1));
            generator.SetPublicKey(keypair.Public);

            var keyUsage = new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation);
            generator.AddExtension(X509Extensions.KeyUsage, true, keyUsage);

            var signFactory = new GostSignatureFactory(
                RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512.ToString(),
                keypair.Private);

            privateKey = keypair.Private;

            return generator.Generate(signFactory);
        }

        public static byte[] CreatePKCS12(X509Certificate certificate, AsymmetricKeyParameter privateKey, string password)
        {
            var builder = new Pkcs12StoreBuilder();
            builder.SetUseDerEncoding(true);
            var store = builder.Build();

            var certEntry = new X509CertificateEntry(certificate);
            store.SetKeyEntry("some_alias",
                new AsymmetricKeyEntry(privateKey),
                new X509CertificateEntry[] { certEntry });

            byte[] pfxBytes;
            using (MemoryStream stream = new MemoryStream()) {
                store.Save(stream, password.ToCharArray(), new SecureRandom());
                pfxBytes = stream.ToArray();
            }

            return Pkcs12Utilities.ConvertToDefiniteLength(pfxBytes);
        }
    }
}

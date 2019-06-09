# bc-xml-security

Implementation of the [XML Security standards](https://www.w3.org/standards/xml/security) using [Bouncy Castle](http://www.bouncycastle.org/csharp):
- XML Signature Syntax and Processing
- XML Encryption Syntax and Processing

Adapted from [corefx](https://github.com/dotnet/corefx/tree/master/src/System.Security.Cryptography.Xml) sources.

### Example

See [samples folder](https://github.com/kmvi/bc-xml-security/tree/master/samples)

```csharp
// Load certificate and private key form PKCS12 container
var store = new Pkcs12Store();
using (var strm = File.OpenRead(@"d:\123.pfx"))
	store.Load(strm, new [] { '1' });
var alias = store.Aliases.Cast<string>().First();
var cert = store.GetCertificate(alias).Certificate;
var privKey = store.GetKey(alias).Key;

// Element to sign
var doc = new XmlDocument();
doc.LoadXml("<a id=\"test\">some test node</a>");

var sgn = new SignedXml(doc);
var rf = new Reference();
rf.AddTransform(new XmlDsigEnvelopedSignatureTransform());
rf.AddTransform(new XmlDsigC14NTransform());
rf.DigestMethod = SignedXml.XmlDsigSHA1Url;
rf.Uri = "#test";

sgn.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
sgn.AddReference(rf);
sgn.KeyInfo = new KeyInfo();
sgn.KeyInfo.AddClause(new KeyInfoX509Data(cert));
sgn.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
sgn.SigningKey = privKey;

sgn.ComputeSignature();
var signature = sgn.GetXml(); // <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"> ...

// Check signature
var sgn2 = new SignedXml(doc);
sgn2.LoadXml(signature);
sgn2.CheckSignature(cert, true);
```

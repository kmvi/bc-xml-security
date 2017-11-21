# bc-signedxml
XML Signature with Bouncy Castle

### TODO
- [ ] EncryptedXml
- [x] GOST support

### Example

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
doc.LoadXml("<a id=\"aaa\">test</a>");

var sgn = new SignedXml(doc);
var rf = new Reference();
rf.AddTransform(new XmlDsigEnvelopedSignatureTransform());
rf.AddTransform(new XmlDsigC14NTransform());
rf.DigestMethod = SignedXml.XmlDsigSHA1Url;
rf.Uri = "#aaa";

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

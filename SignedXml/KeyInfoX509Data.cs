// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class KeyInfoX509Data : KeyInfoClause
    {
        // An array of certificates representing the certificate chain 
        private ArrayList _certificates = null;
        // An array of issuer serial structs
        private ArrayList _issuerSerials = null;
        // An array of SKIs
        private ArrayList _subjectKeyIds = null;
        // An array of subject names
        private ArrayList _subjectNames = null;
        // A raw byte data representing a certificate revocation list
        private byte[] _CRL = null;

        //
        // public constructors
        //

        public KeyInfoX509Data() { }

        public KeyInfoX509Data(byte[] rgbCert)
        {
            if (rgbCert != null) {
                var parser = new X509CertificateParser();
                AddCertificate(parser.ReadCertificate(rgbCert));
            }
        }

        public KeyInfoX509Data(X509Certificate cert)
        {
            AddCertificate(Utils.CloneCertificate(cert));
        }

        public KeyInfoX509Data(X509Certificate cert, IEnumerable<X509Certificate> additional, X509IncludeOption includeOption)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            X509Certificate certificate = Utils.CloneCertificate(cert);
            IList<X509Certificate> chain = null;
            switch (includeOption)
            {
                case X509IncludeOption.ExcludeRoot:
                    // Build the certificate chain
                    chain = Utils.BuildCertificateChain(cert, additional);

                    // Can't honor the option if we only have a partial chain.
                    /*if ((chain.ChainStatus.Length > 0) &&
                        ((chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain))
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Partial_Chain);
                    }*/

                    for (int index = 0; index < (Utils.IsSelfSigned(chain) ? 1 : chain.Count - 1); index++)
                    {
                        AddCertificate(chain[index]);
                    }
                    break;
                case X509IncludeOption.EndCertOnly:
                    AddCertificate(certificate);
                    break;
                case X509IncludeOption.WholeChain:
                    // Build the certificate chain
                    chain = Utils.BuildCertificateChain(cert, additional);

                    // Can't honor the option if we only have a partial chain.
                    /*if ((chain.ChainStatus.Length > 0) &&
                        ((chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain))
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Partial_Chain);
                    }*/

                    foreach (var element in chain)
                    {
                        AddCertificate(element);
                    }
                    break;
            }
        }

        //
        // public properties
        //

        public ArrayList Certificates
        {
            get { return _certificates; }
        }

        public void AddCertificate(X509Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            if (_certificates == null)
                _certificates = new ArrayList();

            X509Certificate x509 = certificate;
            _certificates.Add(x509);
        }

        public ArrayList SubjectKeyIds
        {
            get { return _subjectKeyIds; }
        }

        public void AddSubjectKeyId(byte[] subjectKeyId)
        {
            if (_subjectKeyIds == null)
                _subjectKeyIds = new ArrayList();
            _subjectKeyIds.Add(subjectKeyId);
        }

        public void AddSubjectKeyId(string subjectKeyId)
        {
            if (_subjectKeyIds == null)
                _subjectKeyIds = new ArrayList();
            _subjectKeyIds.Add(Utils.DecodeHexString(subjectKeyId));
        }

        public ArrayList SubjectNames
        {
            get { return _subjectNames; }
        }

        public void AddSubjectName(string subjectName)
        {
            if (_subjectNames == null)
                _subjectNames = new ArrayList();
            _subjectNames.Add(subjectName);
        }

        public ArrayList IssuerSerials
        {
            get { return _issuerSerials; }
        }

        public void AddIssuerSerial(string issuerName, string serialNumber)
        {
            if (string.IsNullOrEmpty(issuerName))
                throw new ArgumentException(SR.Arg_EmptyOrNullString, "issuerName");

            if (string.IsNullOrEmpty(serialNumber))
                throw new ArgumentException(SR.Arg_EmptyOrNullString, "serialNumber");

            BigInteger h;
            try {
                h = new BigInteger(serialNumber);
            } catch (Exception) {
                throw new ArgumentException(SR.Cryptography_Xml_InvalidX509IssuerSerialNumber, "serialNumber");
            }

            if (_issuerSerials == null)
                _issuerSerials = new ArrayList();
            _issuerSerials.Add(Utils.CreateX509IssuerSerial(issuerName, h.ToString()));
        }

        // When we load an X509Data from Xml, we know the serial number is in decimal representation.
        internal void InternalAddIssuerSerial(string issuerName, string serialNumber)
        {
            if (_issuerSerials == null)
                _issuerSerials = new ArrayList();
            _issuerSerials.Add(Utils.CreateX509IssuerSerial(issuerName, serialNumber));
        }

        public byte[] CRL
        {
            get { return _CRL; }
            set { _CRL = value; }
        }

        //
        // private methods
        //

        private void Clear()
        {
            _CRL = null;
            if (_subjectKeyIds != null) _subjectKeyIds.Clear();
            if (_subjectNames != null) _subjectNames.Clear();
            if (_issuerSerials != null) _issuerSerials.Clear();
            if (_certificates != null) _certificates.Clear();
        }

        //
        // public methods
        //

        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return GetXml(xmlDocument);
        }

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement x509DataElement = xmlDocument.CreateElement("X509Data", SignedXml.XmlDsigNamespaceUrl);

            if (_issuerSerials != null)
            {
                foreach (X509IssuerSerial issuerSerial in _issuerSerials)
                {
                    XmlElement issuerSerialElement = xmlDocument.CreateElement("X509IssuerSerial", SignedXml.XmlDsigNamespaceUrl);
                    XmlElement issuerNameElement = xmlDocument.CreateElement("X509IssuerName", SignedXml.XmlDsigNamespaceUrl);
                    issuerNameElement.AppendChild(xmlDocument.CreateTextNode(issuerSerial.IssuerName));
                    issuerSerialElement.AppendChild(issuerNameElement);
                    XmlElement serialNumberElement = xmlDocument.CreateElement("X509SerialNumber", SignedXml.XmlDsigNamespaceUrl);
                    serialNumberElement.AppendChild(xmlDocument.CreateTextNode(issuerSerial.SerialNumber));
                    issuerSerialElement.AppendChild(serialNumberElement);
                    x509DataElement.AppendChild(issuerSerialElement);
                }
            }

            if (_subjectKeyIds != null)
            {
                foreach (byte[] subjectKeyId in _subjectKeyIds)
                {
                    XmlElement subjectKeyIdElement = xmlDocument.CreateElement("X509SKI", SignedXml.XmlDsigNamespaceUrl);
                    subjectKeyIdElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(subjectKeyId)));
                    x509DataElement.AppendChild(subjectKeyIdElement);
                }
            }

            if (_subjectNames != null)
            {
                foreach (string subjectName in _subjectNames)
                {
                    XmlElement subjectNameElement = xmlDocument.CreateElement("X509SubjectName", SignedXml.XmlDsigNamespaceUrl);
                    subjectNameElement.AppendChild(xmlDocument.CreateTextNode(subjectName));
                    x509DataElement.AppendChild(subjectNameElement);
                }
            }

            if (_certificates != null)
            {
                foreach (X509Certificate certificate in _certificates)
                {
                    XmlElement x509Element = xmlDocument.CreateElement("X509Certificate", SignedXml.XmlDsigNamespaceUrl);
                    x509Element.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(certificate.GetEncoded())));
                    x509DataElement.AppendChild(x509Element);
                }
            }

            if (_CRL != null)
            {
                XmlElement crlElement = xmlDocument.CreateElement("X509CRL", SignedXml.XmlDsigNamespaceUrl);
                crlElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(_CRL)));
                x509DataElement.AppendChild(crlElement);
            }

            return x509DataElement;
        }

        public override void LoadXml(XmlElement element)
        {
            if (element == null)
                throw new ArgumentNullException("element");

            XmlNamespaceManager nsm = new XmlNamespaceManager(element.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlNodeList x509IssuerSerialNodes = element.SelectNodes("ds:X509IssuerSerial", nsm);
            XmlNodeList x509SKINodes = element.SelectNodes("ds:X509SKI", nsm);
            XmlNodeList x509SubjectNameNodes = element.SelectNodes("ds:X509SubjectName", nsm);
            XmlNodeList x509CertificateNodes = element.SelectNodes("ds:X509Certificate", nsm);
            XmlNodeList x509CRLNodes = element.SelectNodes("ds:X509CRL", nsm);

            if ((x509CRLNodes.Count == 0 && x509IssuerSerialNodes.Count == 0 && x509SKINodes.Count == 0
                    && x509SubjectNameNodes.Count == 0 && x509CertificateNodes.Count == 0)) // Bad X509Data tag, or Empty tag
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "X509Data");

            // Flush anything in the lists
            Clear();

            if (x509CRLNodes.Count != 0)
                _CRL = Convert.FromBase64String(Utils.DiscardWhiteSpaces(x509CRLNodes.Item(0).InnerText));

            foreach (XmlNode issuerSerialNode in x509IssuerSerialNodes)
            {
                XmlNode x509IssuerNameNode = issuerSerialNode.SelectSingleNode("ds:X509IssuerName", nsm);
                XmlNode x509SerialNumberNode = issuerSerialNode.SelectSingleNode("ds:X509SerialNumber", nsm);
                if (x509IssuerNameNode == null || x509SerialNumberNode == null)
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "IssuerSerial");
                InternalAddIssuerSerial(x509IssuerNameNode.InnerText.Trim(), x509SerialNumberNode.InnerText.Trim());
            }

            foreach (XmlNode node in x509SKINodes)
            {
                AddSubjectKeyId(Convert.FromBase64String(Utils.DiscardWhiteSpaces(node.InnerText)));
            }

            foreach (XmlNode node in x509SubjectNameNodes)
            {
                AddSubjectName(node.InnerText.Trim());
            }

            var parser = new X509CertificateParser();
            foreach (XmlNode node in x509CertificateNodes)
            {
                var cert = Convert.FromBase64String(Utils.DiscardWhiteSpaces(node.InnerText));
                AddCertificate(parser.ReadCertificate(cert));
            }
        }
    }
}

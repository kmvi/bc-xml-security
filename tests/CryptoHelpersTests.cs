// Licensed to the .NET Foundation under one or more agreements.
// See the LICENSE file in the project root for more information
//

using System;
using System.Xml;
using Xunit;

namespace Org.BouncyCastle.Crypto.Xml.Tests
{
    public class CryptoHelpersTests
    {
        private class CustomTransform : Transform
        {
            public override Type[] InputTypes => throw new NotImplementedException();
            public override Type[] OutputTypes => throw new NotImplementedException();
            public override object GetOutput() => throw new NotImplementedException();
            public override object GetOutput(Type type) => throw new NotImplementedException();
            public override void LoadInnerXml(XmlNodeList nodeList) => throw new NotImplementedException();
            public override void LoadInput(object obj) => throw new NotImplementedException();
            protected override XmlNodeList GetInnerXml() => throw new NotImplementedException();
        }

        [Fact]
        public void CreateCustomTransformFromKnownName()
        {
            CryptoHelpers.SetKnownName<CustomTransform>("urn:custom-transform");
            object result = CryptoHelpers.CreateFromKnownName("urn:custom-transform");

            Assert.NotNull(result);
            Assert.IsType<CustomTransform>(result);
        }
    }
}

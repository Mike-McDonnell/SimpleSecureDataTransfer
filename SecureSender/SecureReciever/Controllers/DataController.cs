using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using SSDT;
using System.Security.Cryptography.X509Certificates;

namespace SecureReciever.Controllers
{
    public class DataController : ApiController
    {
        // POST: api/Data
        public void Post(Envelope senvelope)
        {
            X509Certificate2 ServerBsPublicCert = SSDT.CertifcateUtilities.GetCertificateFromStore(senvelope.enc_ref, StoreLocation.CurrentUser);

            var decryptedData = SSDT.Decryptor.DeyryptEnvelope(senvelope, ServerBsPublicCert);

        }
    }
}

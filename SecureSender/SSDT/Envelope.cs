using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SSDT
{
    public class Envelope
    {
        public string object_type { get; } = "http://jsonenc.info/json-encryption/";

        public byte[] enc_data { get; set; }

        public byte[] enc_key { get; set; }

        public byte[] enc_iv { get; set; }

        public CipherMode enc_type { get; set; }

        public string enc_ref { get; set; }
    }
}

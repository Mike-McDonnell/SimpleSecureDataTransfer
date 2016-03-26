using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using SSDT;

namespace SecureSender
{
    class Program
    {
        static void Main(string[] args)
        {
            X509Certificate2 ServerBsPublicCert = new X509Certificate2("c:\\mike.cer");

            try
            {
                string data = "Data to encrypt";

                var envelope = Encryptor.EncryptAndEnvelope(data, ServerBsPublicCert);

                Encryptor.SendSecureData(envelope, "http://localhost:13848/api/Data");

                Console.ReadLine();

            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }
    }
}

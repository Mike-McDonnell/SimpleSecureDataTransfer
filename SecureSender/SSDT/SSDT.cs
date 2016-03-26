﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSDT
{
    public class Encryptor
    {
        public static Envelope EncryptAndEnvelope(string data, X509Certificate2 publicCertificate)
        {
            using (AesCryptoServiceProvider Aes = new AesCryptoServiceProvider())
            {
                byte[] encryptedData = Encrypt(data, Aes.Key, Aes.IV);
                byte[] encryptedKey = EncryptKey(Aes.Key, publicCertificate.PublicKey.Key);

                return new Envelope() { enc_data = encryptedData, enc_key = encryptedKey, enc_iv = Aes.IV, enc_type = Aes.Mode, enc_ref = publicCertificate.Subject };
            }
        }


        public static async Task<HttpResponseMessage> SendSecureData(Envelope envelope, string Url)
        {
            var client = new HttpClient();

            var jsonEnvelope = Newtonsoft.Json.JsonConvert.SerializeObject(envelope);
            return await client.PostAsync(Url, new StringContent(jsonEnvelope, Encoding.UTF8, "application/json"));
        }

        private static byte[] EncryptKey(byte[] AesSymmetricKey, AsymmetricAlgorithm AsymmetricPublicKey)
        {
            RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(AsymmetricPublicKey);
            return keyFormatter.CreateKeyExchange(AesSymmetricKey, typeof(Aes));
        }

        static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider() { Key = Key, IV = IV })
            {
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV), CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        return msEncrypt.ToArray();
                    }
                }
            }
        }
    }
}

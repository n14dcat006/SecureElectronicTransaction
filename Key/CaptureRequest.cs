using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Message
{
    public class CaptureRequest
    {
        
        private string signMessage;
        private string encryptMessage;
        private string encryptKeyMessage;
        private string signToken;
        private string encryptToken;
        private string encryptKeyToken;
        private string MerchantCertificate;
        public CaptureRequest(string transID,string maCard, string CVV, string dateValid, double tien, string pubKeyGateway, string signtoken, string encrToken, string enKeyToken)
        {
            Common c = new Common();
            string messageCapture = transID + ":" + c.Random(2)+":" + maCard + ":" + CVV + ":" + dateValid + ":" + tien;
            string MerchantPrivateKey = File.ReadAllText("d:/file/MerchantPrivateKey.xml");
            signMessage = c.Sign(MerchantPrivateKey, messageCapture);
            string key = c.Random(8);
            encryptMessage = c.EncryptDES(messageCapture, key);
            encryptKeyMessage = c.EncryptRSA(pubKeyGateway, key);
            X509Certificate2 certificate2 = new X509Certificate2("d:/file/merchant.crt");
            MerchantCertificate = c.ByteArrayToString(certificate2.GetRawCertData());
            encryptToken = encrToken;
            signToken = signtoken;
            encryptKeyToken = enKeyToken;
        }
        public string ToMessage()
        {
            return signMessage + "-" + encryptMessage + "-" + encryptKeyMessage + "-" + signToken + "-" + encryptToken + "-" + encryptKeyToken + "-" + MerchantCertificate;
        }
        public CaptureRequest(string s1, string s2, string s3, string s4, string s5, string s6, string s7)
        {
            signMessage = s1;
            encryptMessage = s2;
            encryptKeyMessage = s3;
            signToken = s4;
            encryptToken = s5;
            encryptKeyToken = s6;
            MerchantCertificate = s7;
        }
        public bool Verify()
        {
            Common c = new Common();
            string gatewayPrivateKey = File.ReadAllText("d:/file/GatewayPrivateKey.xml");
            string gatewayPublicKey = File.ReadAllText("d:/file/GatewayPublicKey.xml");
            X509Certificate2 certificate2 = new X509Certificate2(c.StringToByteArray(MerchantCertificate));
            string merchantPublicKey = certificate2.GetRSAPublicKey().ToXmlString(false);
            string keyMessage = c.DecryptionRSA(gatewayPrivateKey, encryptKeyMessage);
            string keyToken=c.DecryptionRSA(gatewayPrivateKey, encryptKeyToken);
            string message = c.DecryptDES(encryptMessage, keyMessage);
            string token = c.DecryptDES(encryptToken, keyToken);
            bool verifyMessage = c.Verify(merchantPublicKey, signMessage, message);
            bool verifyToken = c.Verify(gatewayPublicKey, signToken, token);
            if (verifyMessage == true && verifyToken == true)
            {
                string TransIDMessage, TransIDToken;
                TransIDMessage = message.Split(':')[0];
                TransIDToken = token.Split(':')[0];
                if (TransIDMessage.CompareTo(TransIDToken) == 0) return true;
                else return false;
            }
            else return false;
        }
        public string getCatureRequest()
        {
            Common c = new Common();
            string gatewayPrivateKey = File.ReadAllText("d:/file/GatewayPrivateKey.xml");
            X509Certificate2 certificate2 = new X509Certificate2(c.StringToByteArray(MerchantCertificate));
            string keyMessage = c.DecryptionRSA(gatewayPrivateKey, encryptKeyMessage);
            string message = c.DecryptDES(encryptMessage, keyMessage);
            return message;
        }
        public string getRRPID()
        {
            Common c = new Common();
            string gatewayPrivateKey = File.ReadAllText("d:/file/GatewayPrivateKey.xml");
            X509Certificate2 certificate2 = new X509Certificate2(c.StringToByteArray(MerchantCertificate));
            string keyMessage = c.DecryptionRSA(gatewayPrivateKey, encryptKeyMessage);
            string message = c.DecryptDES(encryptMessage, keyMessage);
            string[] split = message.Split(':');
            return split[1];
        }
    }
}

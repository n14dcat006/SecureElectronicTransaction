using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Message;

namespace Customer
{
    class Program
    {
        
        static void Main(string[] args)
        {
            X509Certificate2 customerCertificate, merchantCertificate, gatewayCertificate;
            string customerPrivateKey, merchantPublicKey, gatewayPublicKey;
            bool verify;
            Common c = new Common();
            IPEndPoint iep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1234);
            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(iep);
            //tạo init request gửi tới merchant
            InitiateRequest initiateRequest = new InitiateRequest();
            c.send(initiateRequest.ToMessage(), client);
            //nhận init response từ merchant
            string receiveMessage = c.receive(client);
            string[] initRES = receiveMessage.Split('-');
            merchantCertificate = new X509Certificate2(c.StringToByteArray(initRES[2]));
            gatewayCertificate = new X509Certificate2(c.StringToByteArray(initRES[3]));            
            merchantPublicKey = merchantCertificate.GetRSAPublicKey().ToXmlString(false);
            gatewayPublicKey = gatewayCertificate.GetRSAPublicKey().ToXmlString(false);
            verify = c.Verify(merchantPublicKey, initRES[1], initRES[0]);
            Console.WriteLine("verify init response: " + verify);
            //tạo purchase request
            string[] value = File.ReadAllLines("d:/file/input.txt");
            string[] initREQValue = initRES[0].Split(':');
            InitiateResponse initiateResponse = new InitiateResponse(initREQValue[0], initREQValue[1], initREQValue[2]);
            OrderInfomation oi = new OrderInfomation(Convert.ToInt32(value[0]), Convert.ToInt32(value[1]), DateTime.Now.ToString("ddMMyyyy"), initiateResponse.getTransID(), initiateResponse.getBrandID(),Convert.ToDouble(value[2]));
            PaymentInstructions pi = new PaymentInstructions(value[3], value[4],value[5] , Convert.ToDouble(value[2]), initiateResponse.getTransID(), initiateResponse.getBrandID());
            customerPrivateKey = File.ReadAllText(value[6]);
            customerCertificate = new X509Certificate2(value[7], "123456");
            PurchaseRequest purchaseRequest = new PurchaseRequest(oi.OIToString(), pi.PIToString(), customerPrivateKey, gatewayPublicKey, c.ByteArrayToString(customerCertificate.GetRawCertData()));
            c.send(purchaseRequest.ToMessage(), client);
            //nhận purchase response
            receiveMessage = c.receive(client);
            string[] splitRES = receiveMessage.Split('-');
            PurchaseResponse purchaseResponse = new PurchaseResponse(splitRES[0], splitRES[1], splitRES[2]);
            Console.WriteLine("verify purchase response: " + purchaseResponse.verify());
            //Console.WriteLine(purchaseResponse.getMessage());
            Console.Read();
            
        }
        
    }
}

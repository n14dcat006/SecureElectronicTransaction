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
namespace Gateway
{
    class Program
    {
        static void Main(string[] args)
        {
            IPAddress address = IPAddress.Parse("127.0.0.1");
            TcpListener listener = new TcpListener(address, 1235);
            listener.Start();
            while (true)
            {
                Socket socket = listener.AcceptSocket();
                Thread t = new Thread(new ParameterizedThreadStart(Thread1));
                t.Start(socket);
            }
        }
        public static void Thread1(object sock)
        {
            string sendMessage;
            Common c = new Common();
            Socket socket = (Socket)sock;
            //nhận auth request
            string receiveMessage = c.receive(socket);
            string gatewayPrivateKey = File.ReadAllText("d:/file/gatewayPrivateKey.xml");
            string[] tam = receiveMessage.Split('-');
            AuthorizationRequest authorizationRequest = new AuthorizationRequest(tam[0], tam[1], tam[2], tam[3], tam[4], tam[5], tam[6]);
            Console.WriteLine("verify auth request: " + authorizationRequest.Verify(gatewayPrivateKey));
            //chuyển auth request đến issuer
            X509Certificate2 issuerCertificate = new X509Certificate2("d:/file/issuer.crt", "123456");
            string issuerPublicKey = issuerCertificate.GetRSAPublicKey().ToXmlString(false);
            string PI = authorizationRequest.getPI(gatewayPrivateKey);
            string[] splitPI = PI.Split(':');
            PaymentInstructions paymentInstructions = new PaymentInstructions(splitPI[0], splitPI[1], splitPI[2], splitPI[3], splitPI[4], splitPI[5], Convert.ToDouble(splitPI[6]));
            string RRPID = paymentInstructions.getRRPID();
            paymentInstructions.setRRPID(c.Random(2));
            ForwardAuthorizationRequest forwardAuthorization = new ForwardAuthorizationRequest(paymentInstructions.PIToString(), issuerPublicKey);
            sendMessage = forwardAuthorization.ToMessage();
            //kết nối issuer
            IPEndPoint iep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1236);
            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(iep);
            c.send(sendMessage, client);
            //nhận kq response từ issuer
            receiveMessage = c.receive(client);
            string[] splitRES = receiveMessage.Split('-');
            issuerCertificate = new X509Certificate2(c.StringToByteArray(splitRES[2]));
            issuerPublicKey = issuerCertificate.GetRSAPublicKey().ToXmlString(false);
            bool verifyRES = c.Verify(issuerPublicKey, splitRES[1], splitRES[0]);
            Console.WriteLine("verify response from issuer" + verifyRES);
            //tạo và gửi auth response
            string[] splitIssuerRES = splitRES[0].Split(':');
            string message = splitIssuerRES[0] + ":" + RRPID +":" + splitIssuerRES[2] +":" + splitIssuerRES[3];
            CaptureToken token = new CaptureToken(paymentInstructions.getTransID(), paymentInstructions.getCardNumber(), paymentInstructions.getTien());
            X509Certificate2 certificate2 = new X509Certificate2(c.StringToByteArray(authorizationRequest.getMerchantCertificate()));
            string publicKeyMerchant = certificate2.GetRSAPublicKey().ToXmlString(false);
            AuthorizationResponse authorizationResponse = new AuthorizationResponse(message, publicKeyMerchant);
            authorizationResponse.setCaptureToken(token.ToMessage());
            c.send(authorizationResponse.ToMessage(), socket);
            //nhận capture request
            receiveMessage = c.receive(socket);
            string[] splitCapture = receiveMessage.Split('-');
            CaptureRequest captureRequest = new CaptureRequest(splitCapture[0], splitCapture[1], splitCapture[2], splitCapture[3], splitCapture[4], splitCapture[5], splitCapture[6]);
            Console.WriteLine("verify capture request: " + captureRequest.Verify());
            //chuyển capture request tới issuer
            string key=c.Random(8);
            X509Certificate2 certificate = new X509Certificate2("d:/file/gateway.crt");
            sendMessage = c.Sign(gatewayPrivateKey, captureRequest.getCatureRequest())+"-"+c.EncryptDES(captureRequest.getCatureRequest(),key)+"-"+c.EncryptRSA(issuerPublicKey,key)+"-"+c.ByteArrayToString(certificate.GetRawCertData());
            c.send(sendMessage, client);
            //nhận message từ issuer
            receiveMessage = c.receive(client);
            string[] splitCaptureRES = receiveMessage.Split('-');
            issuerCertificate = new X509Certificate2(c.StringToByteArray(splitCaptureRES[2]));
            issuerPublicKey = issuerCertificate.GetRSAPublicKey().ToXmlString(false);
            Console.WriteLine("verify capture response from issuer: " + c.Verify(issuerPublicKey, splitCaptureRES[1], splitCaptureRES[0]));
            //tạo capture response gừi tới merchant
            string[] split = splitCaptureRES[0].Split(':');
            message = split[0] + ":" + captureRequest.getRRPID() + ":" + split[2] + ":" + split[3];
            CaptureResponse captureResponse = new CaptureResponse(message, publicKeyMerchant);
            c.send(captureResponse.ToMessage(), socket);
            Console.Read();
        }
    }
}

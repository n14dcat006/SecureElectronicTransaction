using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Message;

namespace Merchant
{
    class Program
    {
        static void Main(string[] args)
        {
            IPAddress address = IPAddress.Parse("127.0.0.1");
            TcpListener listener = new TcpListener(address, 1234);
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
            string gatewayPublicKey;
            string privateKeyMerchant = File.ReadAllText("d:/file/MerchantPrivateKey.xml");
            Common c = new Common();
            Socket socket = (Socket)sock;
            //nhận init request
            string receiveMessage = c.receive(socket);
            string[] initREQ = receiveMessage.Split('-');
            InitiateRequest initiateRequest = new InitiateRequest(initREQ[0], initREQ[1], initREQ[2], initREQ[3], initREQ[4]);
            //tạo init response
            X509Certificate2 certificateMerchant = new X509Certificate2("d:/file/merchant.crt", "123456");
            X509Certificate2 certificateGateway = new X509Certificate2("d:/file/gateway.crt", "123456");
            gatewayPublicKey = certificateGateway.GetRSAPublicKey().ToXmlString(false);
            InitiateResponse initiateResponse = new InitiateResponse(initiateRequest.getLIDC(), initiateRequest.getLanguage(), initiateRequest.getRRPID(),initiateRequest.getBrandID(), c.ByteArrayToString(certificateMerchant.GetRawCertData()),c.ByteArrayToString(certificateGateway.GetRawCertData()));
            string sendMessage = initiateResponse.ToMessage(privateKeyMerchant);
            c.send(sendMessage, socket);
            //nhận purchase request
            receiveMessage = c.receive(socket);
            string[] purchase = receiveMessage.Split('-');
            PurchaseRequest purchaseRequest = new PurchaseRequest(purchase[0], purchase[1], purchase[2], purchase[3], purchase[4],purchase[5]);
            Console.WriteLine("purchase verify" + purchaseRequest.verify());
            //tạo ủy quyền request gửi tới gateway
            AuthorizationRequest authorizationRequest = new AuthorizationRequest(purchaseRequest.getTransID(), Convert.ToDouble(purchaseRequest.getTien()), privateKeyMerchant, gatewayPublicKey, purchaseRequest.getCustommerCertificate(), c.ByteArrayToString(certificateMerchant.GetRawCertData()), purchaseRequest.getMessageToGateway(), purchaseRequest.getDigitalEnvelop());
            IPEndPoint iep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1235);
            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(iep);
            c.send(authorizationRequest.ToMessage(), client);
            //nhận auth res
            receiveMessage = c.receive(client);
            string[] splitAuthRES = receiveMessage.Split('-');
            AuthorizationResponse authorizationResponse = new AuthorizationResponse(splitAuthRES[0], splitAuthRES[1], splitAuthRES[2], splitAuthRES[3], splitAuthRES[4], splitAuthRES[5], splitAuthRES[6]);
            Console.WriteLine("verify authorization response: " + authorizationResponse.verifyMessage());
            //lưu token
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder();
            builder.DataSource = "localhost";
            builder.UserID = "sa";
            builder.Password = "123456";
            builder.InitialCatalog = "Bank";
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();
                string sql;
                StringBuilder sb = new StringBuilder();
                sb.Clear();
                sb.Append("INSERT Token (TransID, SignToken, EncryptToken, EncryptKey) ");
                sb.Append("VALUES (@id, @sign, @token, @key);");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@id", authorizationResponse.getTransID());
                    command.Parameters.AddWithValue("@sign", authorizationResponse.getSignToken());
                    command.Parameters.AddWithValue("@token", authorizationResponse.getEncryptToken());
                    command.Parameters.AddWithValue("@key", authorizationResponse.getEncryptKeyToken());
                    int rowsAffected = command.ExecuteNonQuery();
                }
                connection.Close();
            }
            //tạo purchase response và gởi customer
            string[] messageRES = authorizationResponse.getMessage().Split(':');
            PurchaseResponse purchaseResponse = new PurchaseResponse(messageRES[0] + ":" + purchaseRequest.getRRPID() + ":" + messageRES[2] + ":" + messageRES[3]);
            c.send(purchaseResponse.ToMessage(), socket);
            //tạo capture request
            string merchantCard = "012541AR09O5";
            string merchantCVV = "012345";
            string merchantDateValid = "25062019";
            //---->lấy token
            string signToken="", encryptToken="", encryptKeyToken="";
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();
                string sql;
                sql = "SELECT TransID, SignToken, EncryptToken, EncryptKey FROM Token;";
                using (SqlCommand command = new SqlCommand(sql, connection))
                {

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (reader.GetString(0).CompareTo(authorizationResponse.getTransID()) == 0)
                            {
                                signToken = reader.GetString(1);
                                encryptToken = reader.GetString(2);
                                encryptKeyToken = reader.GetString(3);
                            }
                        }
                    }
                }
                connection.Close();
            }
            CaptureRequest captureRequest = new CaptureRequest(purchaseRequest.getTransID(), merchantCard, merchantCVV, merchantDateValid, Convert.ToDouble(purchaseRequest.getTien()), gatewayPublicKey, signToken, encryptToken, encryptKeyToken);
            c.send(captureRequest.ToMessage(), client);
            //nhận capture response từ gateway
            receiveMessage = c.receive(client);
            string[] splitCaptureResponse = receiveMessage.Split('-');
            CaptureResponse captureResponse = new CaptureResponse(splitCaptureResponse[0], splitCaptureResponse[1], splitCaptureResponse[2], splitCaptureResponse[3]);
            Console.WriteLine("verify capture response: " + captureResponse.verify());
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();
                string sql;
                StringBuilder sb = new StringBuilder();
                sb.Clear();
                sb.Append("INSERT LogCaptureResponse (SignMessage, EncryptMessage, EncryptKey) ");
                sb.Append("VALUES (@sign, @encrypt, @key);");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@sign", captureResponse.getSignMessage());
                    command.Parameters.AddWithValue("@encrypt", captureResponse.getEncryptMessage());
                    command.Parameters.AddWithValue("@key", captureResponse.getEncryptKey());
                    int rowsAffected = command.ExecuteNonQuery();
                }
                connection.Close();
            }
            Console.Read();
        }
    }
}

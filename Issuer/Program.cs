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
namespace Issuer
{
    public class Program
    {
        static void Main(string[] args)
        {
            IPAddress address = IPAddress.Parse("127.0.0.1");
            TcpListener listener = new TcpListener(address, 1236);
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
            string sendMessage, receiveMessage;
            Common c = new Common();
            Socket socket = (Socket)sock;
            //nhận message từ gateway
            string issuerPrivateKey = File.ReadAllText("d:/file/IssuerPrivateKey.xml");
            receiveMessage = c.receive(socket);
            string[] splitAuthReq = receiveMessage.Split('-');
            ForwardAuthorizationRequest forwardAuthorization = new ForwardAuthorizationRequest(splitAuthReq[0], splitAuthReq[1], splitAuthReq[2],splitAuthReq[3]);
            Console.WriteLine("verify gateway forward authorization: " + forwardAuthorization.verify(issuerPrivateKey));
            string PI = forwardAuthorization.getPI(issuerPrivateKey);
            string cardNumber, CVV, dateValid, transID;
            long tien;
            string[] splitPI = PI.Split(':');
            transID = splitPI[0];
            cardNumber = splitPI[3];
            CVV = splitPI[4];
            dateValid = splitPI[5];
            tien = Convert.ToInt64(splitPI[6]);
            //connect SQL server
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder();
            builder.DataSource = "localhost";
            builder.UserID = "sa";
            builder.Password = "123456";
            builder.InitialCatalog = "Bank";
            bool flag = false;
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();
                
                string sql;
                StringBuilder sb = new StringBuilder();
                sql = "SELECT CardNumber, CVV, DateValid FROM Issuer;";
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    string a;
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            a = reader.GetString(2);
                            if (cardNumber.Equals(reader.GetString(0)) == true && CVV.Equals(reader.GetString(1)) == true && dateValid.Equals(reader.GetString(2)) == true)
                            {
                                flag = true;
                            }
                        }
                    }
                }
                //Console.WriteLine("kq sql server: " + flag);
                //ghi PI vào log Isuuer
                
                sb.Clear();
                sb.Append("INSERT LogIssuer (TransID, CardNumber, Money, Paid) ");
                sb.Append("VALUES (@trans, @cardid, @money, @paid);");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@trans", transID);
                    command.Parameters.AddWithValue("@cardid", cardNumber);
                    command.Parameters.AddWithValue("@money", tien);
                    command.Parameters.AddWithValue("@paid", 0);
                    int rowsAffected = command.ExecuteNonQuery();
                    Console.WriteLine(rowsAffected + " row(s) inserted");
                }
                connection.Close();

            }
            //gửi forward response
            X509Certificate2 issuerCertificate = new X509Certificate2("d:/file/issuer.crt", "123456");
            string issuerCert= c.ByteArrayToString(issuerCertificate.GetRawCertData());
            ForwardAuthorizationResponse authorizationResponse = new ForwardAuthorizationResponse(transID, splitPI[1], 1, "ok", issuerPrivateKey, issuerCert);
            c.send(authorizationResponse.ToMessage(), socket);
            //nhận capture request từ gateway
            receiveMessage = c.receive(socket);
            string[] splitCapture = receiveMessage.Split('-');
            string keyCapture = c.DecryptionRSA(issuerPrivateKey, splitCapture[2]);
            string captureRequest = c.DecryptDES(splitCapture[1], keyCapture);//transid:RRPID:merchantcard:merchantCVV:merchantDatevalid:tien
            X509Certificate2 certificate2 = new X509Certificate2(c.StringToByteArray(splitCapture[3]));
            string gatewayPublicKey = certificate2.GetRSAPublicKey().ToXmlString(false);
            Console.WriteLine("verify capture request: " + c.Verify(gatewayPublicKey, splitCapture[0], captureRequest));
            string merchantCardNumber, merchantCVV, merchantDateValid;
            string[] splitCaptureRequest = captureRequest.Split(':');
            transID = splitCaptureRequest[0];
            string RRPID = splitCaptureRequest[1];
            merchantCardNumber = splitCaptureRequest[2];
            merchantCVV = splitCaptureRequest[3];
            merchantDateValid = splitCaptureRequest[4];
            tien = Convert.ToInt64(splitCaptureRequest[5]);
            //nhập dữ liệu thanh toán vào sql server
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();
                string sql;
                StringBuilder sb = new StringBuilder();
                sb.Clear();
                sb.Append("UPDATE LogIssuer SET Paid = @paid WHERE TransID = @id");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@id", transID);
                    command.Parameters.AddWithValue("@paid", 1);
                    int rowsAffected = command.ExecuteNonQuery();
                }
                string customerCardNumber="";
                sql = "SELECT TransID, CardNumber FROM LogIssuer;";
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    string a;
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            a = reader.GetString(1);
                            if (transID.Equals(reader.GetString(0)) == true)
                            {
                                customerCardNumber = reader.GetString(1);
                            }
                            
                        }
                    }
                }
                long tienBanDau=0;
                sql = "SELECT CardNumber, UsedMoney FROM Issuer;";
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    string a;
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (cardNumber.Equals(reader.GetString(0)) == true)
                            {
                                tienBanDau = reader.GetInt64(1);
                            }

                        }
                    }
                }
                sb.Clear();
                sb.Append("UPDATE Issuer SET UsedMoney = @tien WHERE CardNumber = @id");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@tien", tien+tienBanDau);
                    command.Parameters.AddWithValue("@id", customerCardNumber);
                    int rowsAffected = command.ExecuteNonQuery();
                }
                connection.Close();
            }
            //send message to acquirer
            string message = transID + ":" + merchantCardNumber + ":" + merchantCVV + ":" + merchantDateValid + ":" + tien;
            sendMessage = message +"-"+ c.Sign(issuerPrivateKey, message) + "-" + issuerCert;
            IPEndPoint iep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1237);
            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(iep);
            c.send(sendMessage, client);
            //nhận message từ acquirer
            receiveMessage = c.receive(client);
            string[] splitAcquirer = receiveMessage.Split('-');
            X509Certificate2 acquirerCertificate = new X509Certificate2(c.StringToByteArray(splitAcquirer[2]));
            string acquirerPublicKey = acquirerCertificate.GetRSAPublicKey().ToXmlString(false);
            Console.WriteLine("verify message from acquirer: " + c.Verify(acquirerPublicKey, splitAcquirer[1], splitAcquirer[0]));
            string[] splitAcquirerMessage = splitAcquirer[0].Split(':');
            if (splitAcquirerMessage[1].CompareTo("1") == 0)
            {
                //gửi capture response tới gateway
                message = splitAcquirerMessage[0] + ":" + RRPID + ":" + splitAcquirerMessage[1] + ":" + splitAcquirerMessage[2];
                c.send(message + "-" + c.Sign(issuerPrivateKey, message) + "-" + issuerCert,socket);
            }
            else
            {

            }
            Console.Read();
        }
    }
}

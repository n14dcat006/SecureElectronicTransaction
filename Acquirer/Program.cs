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
namespace Acquirer
{
    class Program
    {
        static void Main(string[] args)
        {
            IPAddress address = IPAddress.Parse("127.0.0.1");
            TcpListener listener = new TcpListener(address, 1237);
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
            receiveMessage = c.receive(socket);
            string[] splitMessage = receiveMessage.Split('-');
            X509Certificate2 certificate2 = new X509Certificate2(c.StringToByteArray(splitMessage[2]));
            string issuerPublicKey = certificate2.GetRSAPublicKey().ToXmlString(false);
            Console.WriteLine("verify message from issuer: " + c.Verify(issuerPublicKey, splitMessage[1], splitMessage[0]));
            string TransID, merchantCardNumber, merchantCVV, merchantDateValid;
            long tien;
            string[] split = splitMessage[0].Split(':');
            TransID = split[0];
            merchantCardNumber = split[1];
            merchantCVV = split[2];
            merchantDateValid = split[3];
            tien = Convert.ToInt64(split[4]);
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
                long tienBanDau = 0;
                sql = "SELECT CardNumber, Money FROM Acquirer;";
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    string a;
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (merchantCardNumber.Equals(reader.GetString(0)) == true)
                            {
                                tienBanDau = reader.GetInt64(1);
                            }

                        }
                    }
                }
                sb.Clear();
                sb.Append("UPDATE Acquirer SET Money = @tien WHERE CardNumber = @id and CVV = @cvv and DateValid = @date");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@id", merchantCardNumber);
                    command.Parameters.AddWithValue("@cvv", merchantCVV);
                    command.Parameters.AddWithValue("@date", merchantDateValid);
                    command.Parameters.AddWithValue("@tien", tien);
                    int rowsAffected = command.ExecuteNonQuery();
                }
                
                sb.Clear();
                sb.Append("INSERT LogAcquirer (TransID, CardNumber, Money) ");
                sb.Append("VALUES (@id, @card, @tien);");
                sql = sb.ToString();
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@id", TransID);
                    command.Parameters.AddWithValue("@card", merchantCardNumber);
                    command.Parameters.AddWithValue("@tien", tien);
                    int rowsAffected = command.ExecuteNonQuery();
                }
                connection.Close();
            }
            //send response to issuer
            string message = TransID + ":" + "1" + ":" + "ok";
            X509Certificate2 acquirerCertificate = new X509Certificate2("d:/file/acquirer.crt", "123456");
            string privateKeyAcquirer = File.ReadAllText("d:/file/AcquirerPrivateKey.xml");
            c.send(message + "-" + c.Sign(privateKeyAcquirer, message) + "-" + c.ByteArrayToString(acquirerCertificate.GetRawCertData()),socket);
            Console.Read();
        }
    }
}

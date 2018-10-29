using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Message
{
    public class ForwardAuthorizationResponse
    {
        private string response;
        private string signedResponse;
        private string issuerCertificate;
        public ForwardAuthorizationResponse(string TransID, string RRPID, int maKQ, string KQ, string issuerPrivateKey, string issuerCert)
        {
            Common c = new Common();
            response = TransID + ":" + RRPID + ":" + maKQ + ":" + KQ;
            signedResponse = c.Sign(issuerPrivateKey, response);
            issuerCertificate = issuerCert;
        }
        public string ToMessage()
        {
            return response + "-" + signedResponse + "-" + issuerCertificate;
        }
    }
}

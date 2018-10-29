using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Customer
{
    class PaymentInfo
    {
        string cardNumber;
        string cvvNumber;
        double payment;
        public PaymentInfo(string card, string cvv, double pay)
        {
            this.cardNumber = card;
            this.cvvNumber = cvv;
            this.payment = pay;
        }
    }
}

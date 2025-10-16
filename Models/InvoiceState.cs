namespace ZatcaIntegration.Models
{
    public class InvoiceState
    {
        public string InvoiceId { get; set; }
        public string Uuid { get; set; }
        public string InvoiceHash { get; set; }
        public string ClearedInvoice { get; set; } // Base64 encoded XML
        public string QrCode { get; set; }
        public string ClearanceStatus { get; set; }
    }
}

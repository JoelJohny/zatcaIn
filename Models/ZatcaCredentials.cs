namespace ZatcaIntegration.Models
{
    public class ZatcaCredentials
    {
        public string BinarySecurityToken { get; set; }
        public string Secret { get; set; }
        public long RequestId { get; set; } // This is the CSID
    }
}

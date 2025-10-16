using System.Text.Json.Serialization;

namespace ZatcaIntegration.Models
{
    public class ProductionCsidRequest
    {
        [JsonPropertyName("compliance_request_id")]
        public string ComplianceRequestId { get; set; }
    }
}

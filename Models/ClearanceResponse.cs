using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ZatcaIntegration.Models
{
    public class ClearanceResponse
    {
        [JsonPropertyName("clearanceStatus")]
        public string ClearanceStatus { get; set; }

        [JsonPropertyName("clearedInvoice")]
        public string ClearedInvoice { get; set; }

        [JsonPropertyName("qrCode")]
        public string QrCode { get; set; }

        [JsonPropertyName("warnings")]
        public List<ZatcaMessage> Warnings { get; set; }

        [JsonPropertyName("errors")]
        public List<ZatcaMessage> Errors { get; set; }
    }

    public class ZatcaMessage
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("code")]
        public string Code { get; set; }

        [JsonPropertyName("category")]
        public string Category { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }
    }
}

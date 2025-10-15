using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZatcaIntegration.Models
{
    /// <summary>
    /// Represents the successful response from the ZATCA compliance check API.
    /// This model is designed to match the exact structure of the JSON response.
    /// </summary>
    public class ComplianceResponse
    {
        [JsonPropertyName("requestID")]
        public long RequestID { get; set; }

        [JsonPropertyName("dispositionMessage")]
        public string DispositionMessage { get; set; }

        [JsonPropertyName("binarySecurityToken")]
        public string BinarySecurityToken { get; set; }

        [JsonPropertyName("secret")]
        public string Secret { get; set; }

        [JsonPropertyName("errors")]
        public JsonElement? Errors { get; set; } // Using JsonElement for flexibility
    }
}


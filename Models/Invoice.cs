using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ZatcaIntegration.Models
{
    public class Invoice
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("uuid")]
        public string Uuid { get; set; }

        [JsonPropertyName("icv")]
        public string Icv { get; set; }

        [JsonPropertyName("issue_date")]
        public string IssueDate { get; set; }

        [JsonPropertyName("issue_time")]
        public string IssueTime { get; set; }

        [JsonPropertyName("supply_date")]
        public string SupplyDate { get; set; }

        [JsonPropertyName("previous_invoice_hash")]
        public string PreviousInvoiceHash { get; set; }

        [JsonPropertyName("seller")]
        public Party Seller { get; set; }

        [JsonPropertyName("customer")]
        public Party Customer { get; set; }

        [JsonPropertyName("items")]
        public List<InvoiceItem> Items { get; set; }

        [JsonPropertyName("totals")]
        public InvoiceTotals Totals { get; set; }
    }

    public class Party
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("vat_number")]
        public string VatNumber { get; set; }

        [JsonPropertyName("crn")]
        public string? Crn { get; set; } // Made this field optional

        [JsonPropertyName("street")]
        public string Street { get; set; }

        [JsonPropertyName("building_number")]
        public string BuildingNumber { get; set; }

        [JsonPropertyName("district")]
        public string District { get; set; }

        [JsonPropertyName("city")]
        public string City { get; set; }

        [JsonPropertyName("postal_code")]
        public string PostalCode { get; set; }

        [JsonPropertyName("region")]
        public string? Region { get; set; } // Made this field optional
    }

    public class InvoiceItem
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("quantity")]
        public int Quantity { get; set; }

        [JsonPropertyName("price")]
        public decimal Price { get; set; }

        [JsonPropertyName("net_price")]
        public decimal NetPrice { get; set; }

        [JsonPropertyName("vat_amount")]
        public decimal VatAmount { get; set; }

        [JsonPropertyName("total_inclusive")]
        public decimal TotalInclusive { get; set; }
    }

    public class InvoiceTotals
    {
        [JsonPropertyName("subtotal")]
        public decimal Subtotal { get; set; }

        [JsonPropertyName("vat")]
        public decimal Vat { get; set; }

        [JsonPropertyName("total")]
        public decimal Total { get; set; }
    }
}


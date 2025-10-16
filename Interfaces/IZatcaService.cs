using System.Threading.Tasks;
using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    
    public interface IZatcaService
    {
       
        string GenerateInvoice();

        Task<string> GenerateCsrAsync();
        Task<string> ComplianceCheckAsync(string otp);
        Task<string> CreateStandardInvoiceJsonAsync(Invoice invoiceData);
        Task<string> CreateCertificatePemAsync();
        Task<string> CreateInvoiceXmlAsync(string invoiceId);
        Task<string> GenerateInvoiceHashAsync(string invoiceId);
        Task<string> GenerateComplianceInvoiceRequestAsync(string invoiceId);
        Task<string> RequestProductionCsidAsync();
        Task<string> ClearInvoiceAsync(string invoiceId);
        Task<string> ClearSingleInvoiceAsync(string invoiceId);
        Task<string> ProcessFullInvoiceWorkflowAsync(Invoice invoiceData);
    }
}

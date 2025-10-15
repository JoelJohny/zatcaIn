using System.Threading.Tasks;
using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    /// <summary>
    /// Defines the contract for ZATCA integration operations.
    /// </summary>
    public interface IZatcaService
    {
        /// <summary>
        /// Generates a sample invoice compliance response.
        /// </summary>
        /// <returns>A string message indicating success.</returns>
        string GenerateInvoice();

        Task<string> GenerateCsrAsync();
        Task<string> ComplianceCheckAsync(string otp);
        Task<string> CreateStandardInvoiceJsonAsync(Invoice invoiceData);
    }
}

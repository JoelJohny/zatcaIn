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
    }
}

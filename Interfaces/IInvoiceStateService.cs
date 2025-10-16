using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    public interface IInvoiceStateService
    {
        void StoreInvoiceState(InvoiceState state);
        InvoiceState GetInvoiceState(string invoiceId);
        void UpdateInvoiceState(string invoiceId, InvoiceState updatedState);
    }
}

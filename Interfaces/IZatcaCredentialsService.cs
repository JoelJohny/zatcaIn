using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    public interface IZatcaCredentialsService
    {
        void SetCredentials(string token, string secret, long requestId);
        ZatcaCredentials GetCredentials();
    }
}


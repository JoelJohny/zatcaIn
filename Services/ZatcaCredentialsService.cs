using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    public class ZatcaCredentialsService : IZatcaCredentialsService
    {
        private ZatcaCredentials _credentials;

        public void SetCredentials(string token, string secret, long requestId)
        {
            _credentials = new ZatcaCredentials
            {
                BinarySecurityToken = token,
                Secret = secret,
                RequestId = requestId
            };
        }

        public ZatcaCredentials GetCredentials()
        {
            return _credentials;
        }
    }
}


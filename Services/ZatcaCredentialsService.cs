namespace ZatcaIntegration.Services
{
    /// <summary>
    /// An in-memory implementation of the credentials service.
    /// NOTE: For production, consider a more persistent and secure storage mechanism.
    /// </summary>
    public class ZatcaCredentialsService : IZatcaCredentialsService
    {
        private string _token;
        private string _secret;

        public (string Token, string Secret) GetCredentials()
        {
            return (_token, _secret);
        }

        public void SetCredentials(string token, string secret)
        {
            _token = token;
            _secret = secret;
        }
    }
}

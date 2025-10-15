namespace ZatcaIntegration.Services
{
    /// <summary>
    /// Defines a contract for a service that stores and retrieves ZATCA API credentials.
    /// </summary>
    public interface IZatcaCredentialsService
    {
        /// <summary>
        /// Stores the API credentials.
        /// </summary>
        /// <param name="token">The binary security token.</param>
        /// <param name="secret">The secret key.</param>
        void SetCredentials(string token, string secret);

        /// <summary>
        /// Retrieves the stored API credentials.
        /// </summary>
        /// <returns>A tuple containing the token and secret.</returns>
        (string Token, string Secret) GetCredentials();
    }
}

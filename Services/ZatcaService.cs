using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    /// <summary>
    /// Implements the logic for ZATCA integration operations.
    /// </summary>
    public class ZatcaService : IZatcaService
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly IZatcaCredentialsService _credentialsService;
        public ZatcaService(IZatcaCredentialsService credentialsService)
        {
            _credentialsService = credentialsService;
        }
        public string GenerateInvoice()
        {
            // In a real application, you would put your complex logic here
            // to generate a compliant XML, sign it, and get it cleared.
            Console.WriteLine("Generating ZATCA compliant invoice...");
            return "Successfully generated and cleared invoice!";
        }

        public async Task<string> GenerateCsrAsync()
        {
            // --- Configuration ---
            var fatooraScriptsPath = Path.Combine(Directory.GetCurrentDirectory(), "Scripts", "fatoora");
            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Certificates");

            var csrConfigFile = Path.Combine(fatooraScriptsPath, "csr-config-example-EN.properties");
            var privateKeyFile = Path.Combine(fatooraScriptsPath, "ec-private-key.pem");
            var outputCsrFile = Path.Combine(outputPath, "certificate.csr");

            // --- Pre-run Checks ---
            if (!File.Exists(csrConfigFile))
            {
                return $"Error: CSR config file not found at '{csrConfigFile}'";
            }
            // if (!File.Exists(privateKeyFile))
            // {
            //     return $"Error: Private key file not found at '{privateKeyFile}'";
            // }

            // Ensure the output directory exists
            Directory.CreateDirectory(outputPath);

            // --- Process Execution ---
            // Build the full command and arguments to be passed to the system's shell.
            // Quoting the paths ensures that spaces in file names are handled correctly.
            var arguments = $"-csr -pem -csrConfig \"{csrConfigFile}\" -privateKey \"{privateKeyFile}\" -generatedCsr \"{outputCsrFile}\" -sim";
            var fullCommand = $"fatoora {arguments}";

            string shellFileName;
            string shellArguments;

            // Determine the correct shell and argument structure based on the operating system.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                shellFileName = "cmd.exe";
                shellArguments = $"/c {fullCommand}"; // /c tells cmd to execute the command and then terminate.
            }
            else
            {
                // For Linux, macOS, etc.
                shellFileName = "/bin/bash";
                shellArguments = $"-c \"{fullCommand}\""; // -c tells bash to execute the command from a string.
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = shellFileName,
                Arguments = shellArguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = fatooraScriptsPath // Set the working directory so 'fatoora' can find its files.
            };

            using (var process = new Process { StartInfo = processStartInfo })
            {
                var output = new StringBuilder();
                var error = new StringBuilder();

                process.OutputDataReceived += (sender, args) => { if (args.Data != null) output.AppendLine(args.Data); };
                process.ErrorDataReceived += (sender, args) => { if (args.Data != null) error.AppendLine(args.Data); };

                try
                {
                    process.Start();

                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    await process.WaitForExitAsync();

                    if (process.ExitCode == 0 && string.IsNullOrWhiteSpace(error.ToString()))
                    {
                        var generatedCsrContent = await File.ReadAllTextAsync(outputCsrFile);
                        return $"CSR generated successfully. Path: {outputCsrFile}\n--- Output ---\n{output}\n--- CSR Content ---\n{generatedCsrContent}";
                    }
                    else
                    {
                        return $"Error generating CSR. Exit Code: {process.ExitCode}\n--- Details ---\nThis error often means the 'fatoora' command is not in your system's PATH, or there is an issue with the arguments provided.\n--- Error ---\n{error}\n--- Output ---\n{output}";
                    }
                }
                catch (Exception ex)
                {
                    return $"An exception occurred while trying to run the command: {ex.Message}";
                }
            }
        }

        public async Task<string> ComplianceCheckAsync(string otp)
        {
            var certificatesPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Certificates");
            var csrFilePath = Path.Combine(certificatesPath, "certificate.csr");

            if (!File.Exists(csrFilePath))
            {
                return $"Error: CSR file not found at '{csrFilePath}'. Please generate the CSR first.";
            }

            try
            {
                var csrContent = await File.ReadAllTextAsync(csrFilePath);
                var csrBytes = Encoding.UTF8.GetBytes(csrContent);
                var csrBase64 = Convert.ToBase64String(csrBytes);

                var requestUrl = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance";
                var requestBody = new { csr = csrBase64 };
                var jsonBody = JsonSerializer.Serialize(requestBody);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Add("OTP", otp);
                request.Headers.Add("Accept-Version", "V2");
                request.Content = content;

                var response = await _httpClient.SendAsync(request);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var complianceResponse = JsonSerializer.Deserialize<ComplianceResponse>(responseBody);
                    if (complianceResponse != null && !string.IsNullOrEmpty(complianceResponse.BinarySecurityToken))
                    {
                        // Store the credentials using the dedicated service
                        _credentialsService.SetCredentials(complianceResponse.BinarySecurityToken, complianceResponse.Secret);
                        return $"Compliance check successful. Credentials have been stored.\n--- Response ---\n{responseBody}";
                    }
                    return $"Error: Compliance check was successful, but the response did not contain the expected data.\n--- Response ---\n{responseBody}";
                }
                else
                {
                    return $"Error during compliance check. Status Code: {response.StatusCode}\n--- Response ---\n{responseBody}";
                }
            }
            catch (Exception ex)
            {
                return $"An exception occurred during the compliance check: {ex.Message}";
            }
        }
        
        public async Task<string> CreateStandardInvoiceJsonAsync(Invoice invoiceData)
        {
            try
            {
                // Configure serializer for pretty-printing the JSON
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true
                };

                var jsonString = JsonSerializer.Serialize(invoiceData, options);

                // Save the JSON to a file
                var invoicesPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices");
                Directory.CreateDirectory(invoicesPath);
                var filePath = Path.Combine(invoicesPath, $"{invoiceData.Id}.json");

                await File.WriteAllTextAsync(filePath, jsonString);

                return $"Successfully created JSON invoice at: {filePath}";
            }
            catch (Exception ex)
            {
                return $"An error occurred during JSON creation: {ex.Message}";
            }
        }
    }
}


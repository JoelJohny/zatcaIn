using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.Options;
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
        private readonly IInvoiceStateService _invoiceStateService;
        private readonly ZatcaApiSettings _zatcaApiSettings;
        public ZatcaService(IZatcaCredentialsService credentialsService, IInvoiceStateService invoiceStateService, IOptions<ZatcaApiSettings> zatcaApiSettings)
        {
            _credentialsService = credentialsService;
            _invoiceStateService = invoiceStateService;
            _zatcaApiSettings = zatcaApiSettings.Value;
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

                var requestUrl = _zatcaApiSettings.ComplianceUrl;;
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
                        _credentialsService.SetCredentials(complianceResponse.BinarySecurityToken, complianceResponse.Secret, complianceResponse.RequestID);
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

                var initialState = new InvoiceState
                {
                    InvoiceId = invoiceData.Id,
                    Uuid = invoiceData.Uuid
                };
                _invoiceStateService.StoreInvoiceState(initialState);

                return $"Successfully created JSON invoice at: {filePath}";
            }
            catch (Exception ex)
            {
                return $"An error occurred during JSON creation: {ex.Message}";
            }
        }
        public async Task<string> CreateCertificatePemAsync()
        {
            try
            {
                var credentials = _credentialsService.GetCredentials();
                if (string.IsNullOrEmpty(credentials.BinarySecurityToken))
                {
                    return "Error: Credentials (binarySecurityToken) not found. Please run the compliance check first.";
                }

                // Decode the token from Base64 and re-encode it with line breaks for proper PEM formatting.
                var tokenBytes = Convert.FromBase64String(credentials.BinarySecurityToken);
                string decodedString = Encoding.UTF8.GetString(tokenBytes);
                // var formattedToken = Convert.ToBase64String(tokenBytes, Base64FormattingOptions.InsertLineBreaks);

                // 1. Format the certificate part from the binary security token
                var certificateContent = $"-----BEGIN CERTIFICATE-----\n{decodedString}\n-----END CERTIFICATE-----\n";

                // 2. Read and reformat the private key part
                var privateKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "Scripts", "fatoora", "ec-private-key.pem");
                if (!File.Exists(privateKeyPath))
                {
                    return $"Error: Private key file not found at '{privateKeyPath}'.";
                }
                var privateKeyContent = await File.ReadAllTextAsync(privateKeyPath);

                // As requested, change the header and footer for the final PEM file
                privateKeyContent = privateKeyContent.Replace("-----BEGIN EC PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----");
                privateKeyContent = privateKeyContent.Replace("-----END EC PRIVATE KEY-----", "-----END PRIVATE KEY-----");

                // 3. Define the new output path
                var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "xml-certificate");
                Directory.CreateDirectory(outputPath);

                // 4. Save the certificate to its own file
                var certificateFilePath = Path.Combine(outputPath, "certificate.pem");
                await File.WriteAllTextAsync(certificateFilePath, certificateContent.Trim());

                // 5. Save the private key to its own file
                var privateKeyFilePath = Path.Combine(outputPath, "ec-private-key.pem");
                await File.WriteAllTextAsync(privateKeyFilePath, privateKeyContent.Trim());

                return $"Successfully created certificate.pem and ec-private-key.pem at: {outputPath}";
            }
            catch (Exception ex)
            {
                return $"An error occurred while creating certificate.pem: {ex.Message}";
            }
        }

        public async Task<string> CreateInvoiceXmlAsync(string invoiceId)
        {
            // --- Configuration ---
            var pythonScriptsDir = Path.Combine(Directory.GetCurrentDirectory(), "Scripts", "Python");
            var pythonScriptPath = Path.Combine(pythonScriptsDir, "zatca_invoice_tool.py");

            var invoiceJsonPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}.json");
            var outputXmlPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}_signed.xml");

            var certPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "xml-certificate", "certificate.pem");
            var keyPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "xml-certificate", "ec-private-key.pem");


            // --- File validation ---
            if (!File.Exists(pythonScriptPath)) return $"Error: Python script not found at '{pythonScriptPath}'";
            if (!File.Exists(invoiceJsonPath)) return $"Error: Invoice JSON file not found for ID '{invoiceId}' at '{invoiceJsonPath}'";
            if (!File.Exists(certPath)) return $"Error: Certificate file not found at '{certPath}'";
            if (!File.Exists(keyPath)) return $"Error: Private key file not found at '{keyPath}'";


            var arguments = $"\"{pythonScriptPath}\" generate --input \"{invoiceJsonPath}\" --output \"{outputXmlPath}\" --key \"{keyPath}\" --cert \"{certPath}\" --external-hasher Fatoora";

            string shellFileName;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                shellFileName = "py";
            }
            else
            {
                shellFileName = "python3";
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = shellFileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = pythonScriptsDir // Run the script from its directory
            };

            using var process = new Process { StartInfo = processStartInfo };
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

                if (process.ExitCode == 0)
                {
                    return $"Successfully created XML at {outputXmlPath}. Python script output:\n{output}";
                }
                else
                {
                    return $"Error creating XML. Exit Code: {process.ExitCode}\n--- Error ---\n{error}\n--- Output ---\n{output}";
                }
            }
            catch (Exception ex)
            {
                return $"An exception occurred while trying to run the Python script: {ex.Message}. Make sure Python is installed and in your system's PATH.";
            }
        }
        public async Task<string> GenerateInvoiceHashAsync(string invoiceId)
        {
            // --- Configuration ---
            var fatooraScriptsPath = Path.Combine(Directory.GetCurrentDirectory(), "Scripts", "fatoora");
            var invoiceXmlPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}_signed.xml");

            if (!File.Exists(invoiceXmlPath))
            {
                return $"Error: Signed invoice XML not found for ID '{invoiceId}' at '{invoiceXmlPath}'";
            }

            var arguments = $"-generateHash -invoice \"{invoiceXmlPath}\"";
            var fullCommand = $"Fatoora {arguments}";

            string shellFileName;
            string shellArguments;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                shellFileName = "cmd.exe";
                shellArguments = $"/c {fullCommand}";
            }
            else
            {
                shellFileName = "/bin/bash";
                shellArguments = $"-c \"{fullCommand}\"";
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = shellFileName,
                Arguments = shellArguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = fatooraScriptsPath
            };

            using var process = new Process { StartInfo = processStartInfo };
            var output = new StringBuilder();
            var error = new StringBuilder();
            string invoiceHash = null;

            process.OutputDataReceived += (sender, args) =>
            {
                if (args.Data != null)
                {
                    output.AppendLine(args.Data);
                    var trimmedLine = args.Data.Trim();
                    var marker = "INVOICE HASH =";
                    // Use a case-insensitive search to make it more robust
                    int index = trimmedLine.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                    if (index > -1)
                    {
                        // Extract the substring that comes after the marker
                        invoiceHash = trimmedLine.Substring(index + marker.Length).Trim();
                    }
                }
            };
            process.ErrorDataReceived += (sender, args) =>
            {
                if (args.Data != null)
                {
                    error.AppendLine(args.Data);
                    var trimmedLine = args.Data.Trim();
                    var marker = "INVOICE HASH =";
                    // Also check the error stream for the hash, as some tools log info there
                    int index = trimmedLine.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                    if (index > -1)
                    {
                        invoiceHash = trimmedLine.Substring(index + marker.Length).Trim();
                    }
                }
            };

            try
            {
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                await process.WaitForExitAsync();

                if (process.ExitCode != 0 || !string.IsNullOrEmpty(error.ToString()))
                {
                    // If we found the hash, but there was also an error, we might still be able to proceed.
                    // However, it's safer to report the error. If the hash was critical, the next step will fail anyway.
                    return $"Error generating hash. Exit Code: {process.ExitCode}\n--- Error ---\n{error}\n--- Output ---\n{output}";
                }

                if (string.IsNullOrEmpty(invoiceHash))
                {
                    return $"Could not find invoice hash in the command output.\n--- Output ---\n{output}";
                }


                var stateUpdate = new InvoiceState { InvoiceHash = invoiceHash };
                _invoiceStateService.UpdateInvoiceState(invoiceId, stateUpdate);

                return $"Successfully generated hash '{invoiceHash}' and updated {invoiceId}_signed.xml.";

            }
            catch (Exception ex)
            {
                return $"An exception occurred: {ex.Message}";
            }
        }
        public async Task<string> GenerateComplianceInvoiceRequestAsync(string invoiceId)
        {
            // --- Configuration ---
            var fatooraScriptsPath = Path.Combine(Directory.GetCurrentDirectory(), "Scripts", "fatoora");
            var invoiceXmlPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}_signed.xml");
            var outputJsonPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}_compliance_request.json");

            if (!File.Exists(invoiceXmlPath))
            {
                return $"Error: Signed invoice XML not found for ID '{invoiceId}' at '{invoiceXmlPath}'";
            }

            var arguments = $"-invoice \"{invoiceXmlPath}\" -invoiceRequest";
            var fullCommand = $"fatoora {arguments}";

            string shellFileName;
            string shellArguments;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                shellFileName = "cmd.exe";
                shellArguments = $"/c {fullCommand}";
            }
            else
            {
                shellFileName = "/bin/bash";
                shellArguments = $"-c \"{fullCommand}\"";
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = shellFileName,
                Arguments = shellArguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = fatooraScriptsPath
            };

            using var process = new Process { StartInfo = processStartInfo };
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

                if (process.ExitCode != 0 || !string.IsNullOrEmpty(error.ToString()))
                {
                    return $"Error generating compliance request JSON. Exit Code: {process.ExitCode}\n--- Error ---\n{error}\n--- Output ---\n{output}";
                }
                
                // Find the generated JSON file in the script's directory
                var generatedFile = new DirectoryInfo(fatooraScriptsPath)
                    .GetFiles("generated-json-request-*.json")
                    .OrderByDescending(f => f.CreationTime)
                    .FirstOrDefault();

                if (generatedFile == null)
                {
                    return $"Error: The command ran successfully, but the expected output JSON file was not found in '{fatooraScriptsPath}'.\n--- Output ---\n{output}";
                }
                
                var jsonContent = await File.ReadAllTextAsync(generatedFile.FullName);
                await File.WriteAllTextAsync(outputJsonPath, jsonContent);
                
                // Clean up the generated file from the script directory
                generatedFile.Delete();

                return $"Successfully created compliance request JSON at: {outputJsonPath}";
            }
            catch (Exception ex)
            {
                return $"An exception occurred: {ex.Message}";
            }
        }
        public async Task<string> RequestProductionCsidAsync()
        {
            try
            {
                // 1. Get the compliance credentials
                var credentials = _credentialsService.GetCredentials();

                if (string.IsNullOrEmpty(credentials.BinarySecurityToken) || string.IsNullOrEmpty(credentials.Secret))
                {
                    return "Error: Compliance credentials not found. Please run the compliance check first.";
                }

                // 2. Prepare the request
                var requestUrl = _zatcaApiSettings.ProductionCsidUrl;;
                var requestBody = new ProductionCsidRequest { ComplianceRequestId = credentials.RequestId.ToString() };
                var jsonBody = JsonSerializer.Serialize(requestBody);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);

                // 3. Set headers, including Basic Authentication
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Add("Accept-Version", "V2");

                var authString = $"{credentials.BinarySecurityToken}:{credentials.Secret}";
                var authBytes = Encoding.UTF8.GetBytes(authString);
                var authBase64 = Convert.ToBase64String(authBytes);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authBase64);

                request.Content = content;

                // 4. Send the request and handle the response
                var response = await _httpClient.SendAsync(request);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var newCredentials = JsonSerializer.Deserialize<ComplianceResponse>(responseBody);
                    if (newCredentials != null && !string.IsNullOrEmpty(newCredentials.BinarySecurityToken))
                    {
                        // Overwrite the old credentials with the new production ones
                        _credentialsService.SetCredentials(newCredentials.BinarySecurityToken, newCredentials.Secret, newCredentials.RequestID);
                        return $"Successfully obtained new production CSID. Credentials have been updated.\n--- Response ---\n{responseBody}";
                    }
                    return $"Error: Production CSID request was successful, but the response did not contain the expected data.\n--- Response ---\n{responseBody}";
                }
                else
                {
                    return $"Error requesting production CSID. Status Code: {response.StatusCode}\n--- Response ---\n{responseBody}";
                }
            }
            catch (Exception ex)
            {
                return $"An exception occurred while requesting the production CSID: {ex.Message}";
            }
        }
        public async Task<string> ClearInvoiceAsync(string invoiceId)
        {
            try
            {
                // 1. Get the production credentials
                var credentials = _credentialsService.GetCredentials();
                if (string.IsNullOrEmpty(credentials.BinarySecurityToken) || string.IsNullOrEmpty(credentials.Secret))
                {
                    return "Error: Production credentials not found. Please request a production CSID first.";
                }

                // 2. Read the compliance request JSON
                var complianceRequestPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}_compliance_request.json");
                if (!File.Exists(complianceRequestPath))
                {
                    return $"Error: Compliance request JSON file not found at '{complianceRequestPath}'.";
                }
                var jsonBody = await File.ReadAllTextAsync(complianceRequestPath);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                // 3. Prepare the request to the clearance API
                var requestUrl =_zatcaApiSettings.ComplianceInvoicesUrl;
                using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);

                // 4. Set headers
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Add("Accept-Language", "en");
                request.Headers.Add("Accept-Version", "V2");

                var authString = $"{credentials.BinarySecurityToken}:{credentials.Secret}";
                var authBytes = Encoding.UTF8.GetBytes(authString);
                var authBase64 = Convert.ToBase64String(authBytes);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authBase64);

                request.Content = content;

                // 5. Send the request and handle the response
                var response = await _httpClient.SendAsync(request);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var clearanceResponse = JsonSerializer.Deserialize<ClearanceResponse>(responseBody);
                    if (clearanceResponse != null)
                    {
                        var stateUpdate = new InvoiceState
                        {
                            ClearanceStatus = clearanceResponse.ClearanceStatus,
                            ClearedInvoice = clearanceResponse.ClearedInvoice,
                            QrCode = clearanceResponse.QrCode
                        };
                        _invoiceStateService.UpdateInvoiceState(invoiceId, stateUpdate);
                    }
                    
                    return $"Invoice cleared successfully. Status: {clearanceResponse?.ClearanceStatus}\n--- Response ---\n{responseBody}";
                }
                else
                {
                    return $"Error clearing invoice. Status Code: {response.StatusCode}\n--- Response ---\n{responseBody}";
                }
            }
            catch (Exception ex)
            {
                return $"An exception occurred during invoice clearance: {ex.Message}";
            }
        }
        public async Task<string> ClearSingleInvoiceAsync(string invoiceId)
        {
            try
            {
                // 1. Get the production credentials
                var credentials = _credentialsService.GetCredentials();
                if (string.IsNullOrEmpty(credentials.BinarySecurityToken) || string.IsNullOrEmpty(credentials.Secret))
                {
                    return "Error: Production credentials not found. Please request a production CSID first.";
                }

                // 2. Read the compliance request JSON
                var complianceRequestPath = Path.Combine(Directory.GetCurrentDirectory(), "Output", "Invoices", $"{invoiceId}_compliance_request.json");
                if (!File.Exists(complianceRequestPath))
                {
                    return $"Error: Compliance request JSON file not found at '{complianceRequestPath}'.";
                }
                var jsonBody = await File.ReadAllTextAsync(complianceRequestPath);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                // 3. Prepare the request to the single clearance API
                var requestUrl = _zatcaApiSettings.SingleClearanceUrl;
                using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);

                // 4. Set headers, including the new 'Clearance-Status' header
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Add("Accept-Language", "en");
                request.Headers.Add("Accept-Version", "V2");
                request.Headers.Add("Clearance-Status", "1");

                var authString = $"{credentials.BinarySecurityToken}:{credentials.Secret}";
                var authBytes = Encoding.UTF8.GetBytes(authString);
                var authBase64 = Convert.ToBase64String(authBytes);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authBase64);

                request.Content = content;

                // 5. Send the request and handle the response
                var response = await _httpClient.SendAsync(request);
                var responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    // The response model should be the same as the other clearance API
                    var clearanceResponse = JsonSerializer.Deserialize<ClearanceResponse>(responseBody);

                    if (clearanceResponse != null)
                    {
                        var stateUpdate = new InvoiceState
                        {
                            ClearanceStatus = clearanceResponse.ClearanceStatus,
                            ClearedInvoice = clearanceResponse.ClearedInvoice,
                            QrCode = clearanceResponse.QrCode
                        };
                        _invoiceStateService.UpdateInvoiceState(invoiceId, stateUpdate);
                    }

                    return $"Single invoice clearance successful. Status: {clearanceResponse?.ClearanceStatus}\n--- Response ---\n{responseBody}";
                }
                else
                {
                    return $"Error clearing single invoice. Status Code: {response.StatusCode}\n--- Response ---\n{responseBody}";
                }
            }
            catch (Exception ex)
            {
                return $"An exception occurred during single invoice clearance: {ex.Message}";
            }
        }
        public async Task<string> ProcessFullInvoiceWorkflowAsync(Invoice invoiceData)
        {
            var results = new StringBuilder();
            
            // Helper function to check for errors
            bool IsError(string result) => result.StartsWith("Error", StringComparison.OrdinalIgnoreCase);

            try
            {
                // Step 1: Create Standard Invoice JSON
                var jsonResult = await CreateStandardInvoiceJsonAsync(invoiceData);
                results.AppendLine($"Step 1 (Create JSON): {jsonResult}");
                if (IsError(jsonResult)) return results.ToString();

                // Step 2: Create Signed Invoice XML
                var xmlResult = await CreateInvoiceXmlAsync(invoiceData.Id);
                results.AppendLine($"Step 2 (Create XML): {xmlResult}");
                if (IsError(xmlResult)) return results.ToString();
                
                // Step 3: Generate Invoice Hash and Update XML
                var hashResult = await GenerateInvoiceHashAsync(invoiceData.Id);
                results.AppendLine($"Step 3 (Generate Hash): {hashResult}");
                if (IsError(hashResult)) return results.ToString();
                
                // Step 4: Generate Compliance Request JSON
                var complianceRequestResult = await GenerateComplianceInvoiceRequestAsync(invoiceData.Id);
                results.AppendLine($"Step 4 (Generate Compliance Request): {complianceRequestResult}");
                if (IsError(complianceRequestResult)) return results.ToString();

                // Step 5: Clear Invoice (Compliance)
                var complianceClearanceResult = await ClearInvoiceAsync(invoiceData.Id);
                results.AppendLine($"Step 5 (Compliance Clearance): {complianceClearanceResult}");
                if (IsError(complianceClearanceResult)) return results.ToString();

                // Step 6: Request Production CSID
                var productionCsidResult = await RequestProductionCsidAsync();
                results.AppendLine($"Step 6 (Request Production CSID): {productionCsidResult}");
                if (IsError(productionCsidResult)) return results.ToString();
                
                // Step 7: Clear Single Invoice (Production)
                var singleClearanceResult = await ClearSingleInvoiceAsync(invoiceData.Id);
                results.AppendLine($"Step 7 (Production Clearance): {singleClearanceResult}");
                if (IsError(singleClearanceResult)) return results.ToString();

                return $"Workflow completed successfully for invoice '{invoiceData.Id}'.\n\n--- Full Log ---\n{results}";
            }
            catch (Exception ex)
            {
                return $"A critical error occurred during the workflow: {ex.Message}\n\n--- Log ---\n{results}";
            }
        }
    }
}


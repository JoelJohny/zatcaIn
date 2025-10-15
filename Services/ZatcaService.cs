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
        public async Task<string> CreateCertificatePemAsync()
        {
            try
            {
                var credentials = _credentialsService.GetCredentials();
                if (string.IsNullOrEmpty(credentials.Token))
                {
                    return "Error: Credentials (binarySecurityToken) not found. Please run the compliance check first.";
                }

                // Decode the token from Base64 and re-encode it with line breaks for proper PEM formatting.
                var tokenBytes = Convert.FromBase64String(credentials.Token);
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


            var arguments = $"\"{pythonScriptPath}\" generate --input \"{invoiceJsonPath}\" --output \"{outputXmlPath}\" --key \"{keyPath}\" --cert \"{certPath}\"";

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

                // --- Update XML with the new hash ---
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true; // Important for keeping the XML format intact
                xmlDoc.Load(invoiceXmlPath);

                // The 'ds' namespace is required to find the DigestValue element
                var nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
                nsmgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

                // Use a more specific XPath to target the correct DigestValue
                var digestValueNode = xmlDoc.SelectSingleNode("//ds:Reference[@Id='invoiceSignedData']/ds:DigestValue", nsmgr);

                if (digestValueNode == null)
                {
                    return "Error: Could not find the <ds:DigestValue> tag within the Reference with Id='invoiceSignedData'.";
                }

                digestValueNode.InnerText = invoiceHash;
                xmlDoc.Save(invoiceXmlPath);

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

                // Assuming the command prints the JSON to standard output. We may need to trim logs.
                var outputString = output.ToString();
                
                // The tool might print logs before the JSON. Let's find the start of the JSON.
                int jsonStartIndex = outputString.IndexOf('{');
                if (jsonStartIndex == -1)
                {
                    return $"Error: Could not find JSON content in the command output.\n--- Output ---\n{outputString}";
                }
                var jsonContent = outputString.Substring(jsonStartIndex);


                await File.WriteAllTextAsync(outputJsonPath, jsonContent);

                return $"Successfully created compliance request JSON at: {outputJsonPath}";
            }
            catch (Exception ex)
            {
                return $"An exception occurred: {ex.Message}";
            }
        }
    }
}


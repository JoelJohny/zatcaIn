using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using ZatcaIntegration.Models;

namespace ZatcaIntegration.Services
{
    public class InvoiceStateService : IInvoiceStateService
    {
        private ConcurrentDictionary<string, InvoiceState> _invoiceStates = new ConcurrentDictionary<string, InvoiceState>();
        private readonly string _filePath;
        private static readonly object _fileLock = new object();

        public InvoiceStateService()
        {
            // Define the path for the JSON file where states will be stored.
            var outputDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Output");
            Directory.CreateDirectory(outputDirectory); // Ensure the directory exists.
            _filePath = Path.Combine(outputDirectory, "invoicestates.json");
            
            // Load existing states from the file when the service starts.
            LoadStatesFromFile();
        }

        public InvoiceState GetInvoiceState(string invoiceId)
        {
            _invoiceStates.TryGetValue(invoiceId, out var state);
            return state;
        }

        public void StoreInvoiceState(InvoiceState state)
        {
            _invoiceStates[state.InvoiceId] = state;
            SaveChangesToFile(); // Save changes whenever a new state is stored.
        }

        public void UpdateInvoiceState(string invoiceId, InvoiceState updatedState)
        {
            var existingState = GetInvoiceState(invoiceId);
            if (existingState != null)
            {
                // This ensures we only update fields that are provided in the update
                if (!string.IsNullOrEmpty(updatedState.InvoiceHash)) existingState.InvoiceHash = updatedState.InvoiceHash;
                if (!string.IsNullOrEmpty(updatedState.ClearedInvoice)) existingState.ClearedInvoice = updatedState.ClearedInvoice;
                if (!string.IsNullOrEmpty(updatedState.QrCode)) existingState.QrCode = updatedState.QrCode;
                if (!string.IsNullOrEmpty(updatedState.ClearanceStatus)) existingState.ClearanceStatus = updatedState.ClearanceStatus;
                
                StoreInvoiceState(existingState); // This will also trigger a save to the file.
            }
        }

        /// <summary>
        /// Saves the current state of all invoices to the JSON file.
        /// </summary>
        private void SaveChangesToFile()
        {
            lock (_fileLock)
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                var jsonString = JsonSerializer.Serialize(_invoiceStates, options);
                File.WriteAllText(_filePath, jsonString);
            }
        }

        /// <summary>
        /// Loads the invoice states from the JSON file into memory.
        /// </summary>
        private void LoadStatesFromFile()
        {
            lock (_fileLock)
            {
                if (!File.Exists(_filePath))
                {
                    return; // No file to load, start fresh.
                }

                try
                {
                    var jsonString = File.ReadAllText(_filePath);
                    if (string.IsNullOrWhiteSpace(jsonString)) return;

                    var states = JsonSerializer.Deserialize<ConcurrentDictionary<string, InvoiceState>>(jsonString);
                    if (states != null)
                    {
                        _invoiceStates = states;
                    }
                }
                catch (JsonException ex)
                {
                    // Handle cases where the JSON file might be corrupted or empty
                    System.Console.WriteLine($"Error reading invoice states from file: {ex.Message}");
                }
            }
        }
    }
}


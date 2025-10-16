# **ZATCA E-Invoicing Integration API**

This project is a .NET Web API designed to facilitate the integration with the Saudi Arabian Zakat, Tax and Customs Authority (ZATCA) for e-invoicing (Fatoora). It provides a complete, step-by-step workflow for generating and clearing invoices as per ZATCA's requirements, wrapping external command-line tools like fatoora and custom Python scripts.

## **Key Features**

* **End-to-End Workflow**: Covers the entire process from Certificate Signing Request (CSR) generation to final invoice clearance.  
* **Step-by-Step API Endpoints**: Each step in the ZATCA process is exposed as a separate API endpoint for granular control and debugging.  
* **Combined Workflow Endpoint**: A single endpoint to run the entire invoice processing sequence for convenience.  
* **External Tool Integration**: Manages the execution of the fatoora Java tool and custom Python scripts for XML signing and processing.  
* **State Management**: Persists the state of each invoice (hash, clearance status, etc.) in a JSON file for data retention.  
* **Configuration Driven**: API endpoints for ZATCA are managed via appsettings.json, allowing for easy switching between sandbox and production environments.

## **Folder Structure**

/ZatcaIntegration  
|  
├── Controllers/            \# API controllers that handle incoming HTTP requests.  
├── Models/                 \# C\# classes representing data structures (e.g., Invoice, API responses).  
├── Services/               \# Contains the core business logic for ZATCA integration.  
├── Properties/             \# Project launch settings.  
├── Scripts/  
│   ├── fatoora/            \# Location for the 'fatoora' command-line tool and its properties files.  
│   └── Python/             \# Location for custom Python scripts (e.g., for XML generation).  
│       └── venv/           \# Recommended location for the Python virtual environment.  
├── Output/                 \# Directory where all generated files (certificates, invoices) are stored.  
│   ├── Certificates/  
│   ├── Invoices/  
│   └── xml certificate/  
├── appsettings.json        \# Configuration file for the application, including ZATCA URLs.  
└── README.md               \# This file.

## **Prerequisites**

Before running this project, you will need the following installed on your system:

1. **.NET 7.0 SDK** (or newer)  
2. **Python 3.x**  
3. The **fatoora** command-line tool.

## **Setup & Installation**

1. **Clone the repository:**  
   git clone \<your-repository-url\>  
   cd ZatcaIntegration

2. **Place External Tools:**  
   * Place the fatoora tool and its related files (e.g., csr-config-example-EN.properties, ec-private-key.pem) inside the /Scripts/fatoora/ directory.  
   * Place your Python script (zatca\_invoice\_tool.py) inside the /Scripts/Python/ directory.  
3. **Create Python Virtual Environment:**  
   * It is highly recommended to use a virtual environment for your Python dependencies.  
   * Navigate to the Python scripts directory:  
     cd Scripts/Python

   * Create and activate the virtual environment:  
     \# On Windows  
     python \-m venv venv  
     .\\venv\\Scripts\\activate

     \# On macOS/Linux  
     python3 \-m venv venv  
     source venv/bin/activate

   * Install any required Python packages (e.g., pip install lxml).  
4. **Restore .NET Dependencies:**  
   * Navigate back to the project root and run:  
     dotnet restore

## **Configuration**

1. **appsettings.json**:  
   * This file contains the URLs for the ZATCA APIs. You can switch between sandbox and production URLs here without changing the code.  
2. **csr-config-example-EN.properties**:  
   * Located in /Scripts/fatoora/, this file must be filled with your company's details to generate a valid CSR.

## **How to Run the Application**

1. **Start the API:**  
   * From the project's root directory (/ZatcaIntegration), run the command:  
     dotnet run

2. **Access Swagger UI:**  
   * Once the application is running, open your web browser and navigate to the Swagger UI to test the endpoints. The URL will typically be:  
     https://localhost:7199/swagger (the port may vary).

## **API Endpoints and Workflow**

The API is designed to be used in a specific sequence. For a full demonstration, you can use the combined workflow endpoint. For testing or debugging, you can call each endpoint individually.

### **Combined Workflow**

This is the recommended endpoint for processing a new invoice from start to finish.

* POST /api/zatca/process-full-invoice  
  * **Body**: Requires the full invoice data in JSON format.  
  * **Description**: Executes the entire ZATCA production clearance workflow in the correct order. The service will stop and report an error if any step fails.

### **Individual Endpoints (For Setup and Step-by-Step Processing)**

**One-Time Onboarding/Setup:**

1. POST /api/zatca/generate-csr: Generates a Certificate Signing Request (.csr) file.  
2. POST /api/zatca/compliance-check: Submits the CSR to ZATCA to get compliance credentials (CSID). Requires an OTP in the request header.  
3. POST /api/zatca/request-production-csid: Uses the compliance CSID to request new production credentials.  
4. POST /api/zatca/create-certificate-pem: Creates the final production certificate.pem and ec-private-key.pem files from the production credentials.

**Per-Invoice Clearance Workflow:**

1. POST /api/zatca/create-invoice-json: Takes invoice data as JSON and saves it as a file.  
2. POST /api/zatca/create-invoice-xml/{invoiceId}: Generates a signed XML file from the invoice JSON using the Python script.  
3. POST /api/zatca/generate-invoice-hash/{invoiceId}: Generates an invoice hash using the fatoora tool and updates the XML file.  
4. POST /api/zatca/generate-compliance-request/{invoiceId}: Creates the final JSON request body needed for the clearance API.  
5. POST /api/zatca/clear-single-invoice/{invoiceId}: Submits the invoice to the ZATCA production clearance API.

### **Utility Endpoints**

* GET /api/zatca/get-credentials: Retrieves the currently stored ZATCA credentials (token, secret, CSID).  
* GET /api/zatca/invoice-status/{invoiceId}: Retrieves all stored data for a specific invoice from the invoicestates.json file.

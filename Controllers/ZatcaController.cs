using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using ZatcaIntegration.Models;
using ZatcaIntegration.Services;

namespace ZatcaIntegration.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ZatcaController : ControllerBase
    {
        private readonly IZatcaService _zatcaService;
        private readonly IInvoiceStateService _invoiceStateService;

        // The service is "injected" here through the constructor
        public ZatcaController(IZatcaService zatcaService, IInvoiceStateService invoiceStateService)
        {
            _zatcaService = zatcaService;
            _invoiceStateService = invoiceStateService;
        }

        [HttpPost("generate-invoice")]
        public IActionResult GenerateNewInvoice()
        {
            try
            {
                var result = _zatcaService.GenerateInvoice();
                return Ok(new { message = result });
            }
            catch (System.Exception ex)
            {
                // Basic error handling
                return StatusCode(500, new { error = "An internal server error occurred.", details = ex.Message });
            }
        }
        [HttpPost("generate-csr")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GenerateCsr()
        {
            try
            {
                var result = await _zatcaService.GenerateCsrAsync();

                // Return a bad request if the service reports a known error
                if (result.StartsWith("Error:"))
                {
                    return BadRequest(new { error = result });
                }

                // Otherwise, return success
                return Ok(new { message = "CSR generation process completed.", details = result });
            }
            catch (System.Exception ex)
            {
                // Catch unexpected exceptions during the process
                return StatusCode(500, new { error = "An internal server error occurred while generating the CSR.", details = ex.Message });
            }
        }

        [HttpPost("compliance-check")]
        public async Task<IActionResult> ComplianceCheck([FromBody] ComplianceCheckRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Otp))
            {
                return BadRequest("OTP is required.");
            }

            var result = await _zatcaService.ComplianceCheckAsync(request.Otp);

            if (result.StartsWith("Error"))
            {
                // Distinguish between client errors (like missing CSR) and server/API errors
                if (result.Contains("not found"))
                {
                    return NotFound(result);
                }
                return BadRequest(result);
            }

            return Ok(result);
        }

        [HttpPost("create-standard-invoice")]
        public async Task<IActionResult> CreateStandardInvoice([FromBody] Invoice invoiceData)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _zatcaService.CreateStandardInvoiceJsonAsync(invoiceData);

            if (result.StartsWith("An error"))
            {
                return StatusCode(500, result); // Internal Server Error
            }

            return Ok(result);
        }

        [HttpPost("create-certificate-pem")]
        public async Task<IActionResult> CreateCertificatePem()
        {
            var result = await _zatcaService.CreateCertificatePemAsync();
            if (result.StartsWith("Error"))
            {
                // Return a 404 Not Found if required files are missing, otherwise a 500 error.
                return result.Contains("not found") ? NotFound(result) : StatusCode(500, result);
            }
            return Ok(result);
        }
        [HttpPost("{invoiceId}/create-xml")]
        [ProducesResponseType(typeof(string), 200)]
        [ProducesResponseType(typeof(string), 400)]
        public async Task<IActionResult> CreateInvoiceXml(string invoiceId)
        {
            if (string.IsNullOrWhiteSpace(invoiceId))
            {
                return BadRequest("Invoice ID cannot be empty.");
            }
            var result = await _zatcaService.CreateInvoiceXmlAsync(invoiceId);
            if (result.StartsWith("Error"))
            {
                return BadRequest(result);
            }
            return Ok(result);
        }

        [HttpPost("generate-invoice-hash/{invoiceId}")]
        public async Task<IActionResult> GenerateInvoiceHash(string invoiceId)
        {
            if (string.IsNullOrEmpty(invoiceId))
            {
                return BadRequest(new { message = "Invoice ID is required." });
            }
            var result = await _zatcaService.GenerateInvoiceHashAsync(invoiceId);
            if (result.StartsWith("Error"))
            {
                return BadRequest(new { message = result });
            }
            return Ok(new { message = result });
        }
        [HttpPost("generate-compliance-request/{invoiceId}")]
        public async Task<IActionResult> GenerateComplianceRequest(string invoiceId)
        {
            var result = await _zatcaService.GenerateComplianceInvoiceRequestAsync(invoiceId);
            if (result.StartsWith("Error"))
            {
                return BadRequest(new { message = result });
            }
            return Ok(new { message = result });
        }
        [HttpPost("request-production-csid")]
        public async Task<IActionResult> RequestProductionCsid()
        {
            var result = await _zatcaService.RequestProductionCsidAsync();
            if (result.StartsWith("Error"))
            {
                return BadRequest(new { message = result });
            }
            return Ok(new { message = result });
        }
        [HttpPost("clear-invoice/{invoiceId}")]
        public async Task<IActionResult> ClearInvoice(string invoiceId)
        {
            var result = await _zatcaService.ClearInvoiceAsync(invoiceId);
            if (result.StartsWith("Error"))
            {
                return BadRequest(new { message = result });
            }
            return Ok(new { message = result });
        }
        [HttpPost("clear-single-invoice/{invoiceId}")]
        public async Task<IActionResult> ClearSingleInvoice(string invoiceId)
        {
            var result = await _zatcaService.ClearSingleInvoiceAsync(invoiceId);
            if (result.StartsWith("Error"))
            {
                return BadRequest(new { message = result });
            }
            return Ok(new { message = result });
        }
        [HttpGet("invoice-status/{invoiceId}")]
        public IActionResult GetInvoiceStatus(string invoiceId)
        {
            var state = _invoiceStateService.GetInvoiceState(invoiceId);
            if (state == null)
            {
                return NotFound(new { message = $"No stored data found for invoice ID '{invoiceId}'." });
            }
            return Ok(state);
        }
        [HttpPost("process-full-invoice")]
        public async Task<IActionResult> ProcessFullInvoiceWorkflow([FromBody] Invoice invoiceData)
        {
            if (invoiceData == null || string.IsNullOrEmpty(invoiceData.Id))
            {
                return BadRequest(new { message = "Valid invoice data with an ID is required." });
            }
            var result = await _zatcaService.ProcessFullInvoiceWorkflowAsync(invoiceData);
            return Ok(new { message = result });
        }
    }
}

 public class ComplianceCheckRequest
    {
        [Required]
        public string Otp { get; set; }
    }

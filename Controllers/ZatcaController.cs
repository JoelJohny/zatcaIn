using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using ZatcaIntegration.Services;

namespace ZatcaIntegration.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ZatcaController : ControllerBase
    {
        private readonly IZatcaService _zatcaService;

        // The service is "injected" here through the constructor
        public ZatcaController(IZatcaService zatcaService)
        {
            _zatcaService = zatcaService;
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
    }
}

 public class ComplianceCheckRequest
    {
        [Required]
        public string Otp { get; set; }
    }

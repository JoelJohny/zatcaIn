using Microsoft.AspNetCore.Mvc;
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
    }
}

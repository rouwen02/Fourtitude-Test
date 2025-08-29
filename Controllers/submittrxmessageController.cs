using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace Fourtitude_Test.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class submittrxmessageController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public submittrxmessageController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        public IResult Post()
        {
            try
            {
                // Read and parse the JSON request
                Stream req = Request.Body;
                string json = new StreamReader(req).ReadToEndAsync().Result;
                dynamic? data = Newtonsoft.Json.JsonConvert.DeserializeObject(json);

                if (data == null)
                    return Results.Json(new { result = 0, resultmessage = "Invalid JSON format" });

                // Validation
                var missingField = GetMissingRequiredField(data);
                if (missingField != null)
                    return Results.Json(new { result = 0, resultmessage = $"{missingField} is Required." });

                if (!ValidateTimestamp(data.timestamp?.ToString()))
                    return Results.Json(new { result = 0, resultmessage = "Expired." });

                if (!ValidatePartnerCredentials(data.partnerkey?.ToString(), data.partnerpassword?.ToString()))
                    return Results.Json(new { result = 0, resultmessage = "Access Denied!" });

                if (!ValidateSignature(data))
                    return Results.Json(new { result = 0, resultmessage = "Access Denied!" });

                long totalAmount = (long)data.totalamount;
                if (totalAmount <= 0)
                    return Results.Json(new { result = 0, resultmessage = "Total amount must be positive" });

                if (data.items != null)
                {
                    var items = (IEnumerable<dynamic>)data.items;
                    if (items.Any())
                    {
                        var validationError = ValidateItemsWithError(items);
                        if (validationError != null)
                            return Results.Json(new { result = 0, resultmessage = validationError });

                        if (!ValidateTotalAmountMatchesItems(totalAmount, items))
                            return Results.Json(new { result = 0, resultmessage = "Invalid Total Amount." });
                    }
                }

                // Process the transaction
                var result = ProcessTransactionBusinessLogic(data);
                return Results.Json(result);
            }
            catch
            {
                return Results.Json(new { result = 0, resultmessage = "Internal server error" }, statusCode: 500);
            }
        }

        private string? GetMissingRequiredField(dynamic data)
        {
            if (string.IsNullOrEmpty(data.partnerkey?.ToString())) return "partnerkey";
            if (string.IsNullOrEmpty(data.partnerrefno?.ToString())) return "partnerrefno";
            if (string.IsNullOrEmpty(data.partnerpassword?.ToString())) return "partnerpassword";
            if (string.IsNullOrEmpty(data.timestamp?.ToString())) return "timestamp";
            if (string.IsNullOrEmpty(data.sig?.ToString())) return "sig";
            return null;
        }

        private bool ValidateTimestamp(string timestampString)
        {
            return DateTime.TryParse(timestampString, out var requestTime) &&
                   Math.Abs((DateTime.UtcNow - requestTime).TotalMinutes) <= 5;
        }

        private bool ValidatePartnerCredentials(string partnerKey, string partnerPassword)
        {
            var allowedPartners = _configuration.GetSection("AllowedPartners").Get<Dictionary<string, string>>();
            return allowedPartners != null &&
                   allowedPartners.ContainsKey(partnerKey) &&
                   DecodeBase64(partnerPassword) == allowedPartners[partnerKey];
        }

        private bool ValidateSignature(dynamic data)
        {
            if (!DateTime.TryParse(data.timestamp?.ToString(), out DateTime timestamp))
                return false;

            var sigTimestamp = timestamp.ToString("yyyyMMddHHmmss");
            var signatureString = $"{sigTimestamp}{data.partnerkey}{data.partnerrefno}{data.totalamount}{data.partnerpassword}";

            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(signatureString));
            var hexHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            var hexBytes = Enumerable.Range(0, hexHash.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hexHash.Substring(x, 2), 16))
                .ToArray();

            var computedSig = Convert.ToBase64String(hexBytes);
            return computedSig == data.sig?.ToString();
        }

        private string? ValidateItemsWithError(IEnumerable<dynamic> items)
        {
            foreach (var item in items)
            {
                if (string.IsNullOrEmpty(item.partneritemref?.ToString()))
                    return "Item reference cannot be null or empty";
                if (string.IsNullOrEmpty(item.name?.ToString()))
                    return "Item name cannot be null or empty";

                int qty = (int)item.qty;
                if (qty <= 0 || qty > 5)
                    return "Item quantity must be between 1 and 5";

                long unitPrice = (long)item.unitprice;
                if (unitPrice <= 0)
                    return "Item unit price must be positive";
            }
            return null;
        }

        private bool ValidateTotalAmountMatchesItems(long totalAmount, IEnumerable<dynamic> items)
        {
            long calculatedTotal = 0;
            foreach (var item in items)
            {
                int qty = (int)item.qty;
                long unitPrice = (long)item.unitprice;
                calculatedTotal += qty * unitPrice;
            }
            return calculatedTotal == totalAmount;
        }

        private object ProcessTransactionBusinessLogic(dynamic data)
        {
            long totalAmount = (long)data.totalamount;
            long totalDiscount = totalAmount > 5000 ? (long)(totalAmount * 0.1) : 0;
            long finalAmount = totalAmount - totalDiscount;

            return new
            {
                result = 1,
                totalamount = totalAmount,
                totaldiscount = totalDiscount,
                finalamount = finalAmount
            };
        }

        private string DecodeBase64(string base64String)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64String));
        }
    }
}

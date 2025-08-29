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
                var missingField = ValidateRequiredField(data);
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

        private string? ValidateRequiredField(dynamic data)
        {
            if (string.IsNullOrEmpty(data.partnerkey?.ToString())) return "partnerkey";
            if (string.IsNullOrEmpty(data.partnerrefno?.ToString())) return "partnerrefno";
            if (string.IsNullOrEmpty(data.partnerpassword?.ToString())) return "partnerpassword";
            if (string.IsNullOrEmpty(data.totalamount?.ToString())) return "totalamount";
            if (string.IsNullOrEmpty(data.timestamp?.ToString())) return "timestamp";
            if (string.IsNullOrEmpty(data.sig?.ToString())) return "sig";
            return null;
        }

        private bool ValidateTimestamp(string timestampString)
        {
            if (!DateTime.TryParse(timestampString, out var requestTime))
                return false;

            // Adjust server time to UTC+8
            //var serverTime = DateTime.UtcNow.AddHours(8);
            var serverTime = DateTime.Parse("2024-08-15 02:12:00 AM");
            var timeDifference = Math.Abs((serverTime - requestTime).TotalMinutes);

            return timeDifference <= 5; // ±5 minutes tolerance
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

            // Convert hash bytes to hexadecimal string
            var hexHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            // Convert hexadecimal string to UTF-8 bytes and then to Base64
            var hexBytes = Encoding.UTF8.GetBytes(hexHash);
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
            long totalAmountCents = (long)data.totalamount;

            // Calculate base discount percentage
            decimal totalAmountMyr = totalAmountCents / 100m;
            decimal baseDiscountPercent = CalculateBaseDiscount(totalAmountMyr);

            // Calculate conditional discounts
            decimal conditionalDiscountPercent = CalculateConditionalDiscounts(totalAmountMyr);

            // Calculate total discount percentage
            decimal totalDiscountPercent = baseDiscountPercent + conditionalDiscountPercent;

            // Apply maximum discount cap of 20%
            if (totalDiscountPercent > 20m)
            {
                totalDiscountPercent = 20m;
            }

            // Calculate discount amount in cents
            long totalDiscountCents = (long)(totalAmountCents * (totalDiscountPercent / 100m));
            long finalAmountCents = totalAmountCents - totalDiscountCents;

            return new
            {
                result = 1,
                totalamount = totalAmountCents,
                totaldiscount = totalDiscountCents,
                finalamount = finalAmountCents
            };
        }

        private decimal CalculateBaseDiscount(decimal totalAmountMyr)
        {
            if (totalAmountMyr < 200m)
                return 0m;
            else if (totalAmountMyr >= 200m && totalAmountMyr <= 500m)
                return 5m;
            else if (totalAmountMyr >= 501m && totalAmountMyr <= 800m)
                return 7m;
            else if (totalAmountMyr >= 801m && totalAmountMyr <= 1200m)
                return 10m;
            else // totalAmountMyr > 1200m
                return 15m;
        }

        private decimal CalculateConditionalDiscounts(decimal totalAmountMyr)
        {
            decimal conditionalDiscount = 0m;

            // Prime number above MYR 500: additional 8% discount
            if (totalAmountMyr > 500m && IsPrime((long)totalAmountMyr))
            {
                conditionalDiscount += 8m;
            }

            // Ends with digit 5 and above MYR 900: additional 10% discount
            if (totalAmountMyr > 900m && EndsWithFive(totalAmountMyr))
            {
                conditionalDiscount += 10m;
            }

            return conditionalDiscount;
        }

        private bool IsPrime(long number)
        {
            if (number <= 1) return false;
            if (number == 2) return true;
            if (number % 2 == 0) return false;

            var boundary = (long)Math.Floor(Math.Sqrt(number));

            for (long i = 3; i <= boundary; i += 2)
            {
                if (number % i == 0)
                    return false;
            }

            return true;
        }

        private bool EndsWithFive(decimal amount)
        {
            return Math.Abs(amount % 10) == 5;
        }

        private string DecodeBase64(string base64String)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64String));
        }
    }
}

using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace FileScannerOPSWAT;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("SAMPLE INPUT COMMAND:");
        string filePath = Console.ReadLine();
        string apiKey = ""; //Here you will have to provide your apiKey
        Console.WriteLine("SAMPLE OUTPUT:");
        try
        {
            await PerformHashLookup(apiKey, filePath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }

    //This function calculates the sha256 hash of the file that is stored at the given path
    static string CalculateSHA256(string filePath)
    {
        using (FileStream stream = File.OpenRead(filePath))
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }
    }

    //This function performs a hash lookup against metadefender.opswat.com to check for cached results
    static async Task PerformHashLookup(string apiKey, string filePath)
    {
        string hash = CalculateSHA256(filePath);
        var client = new HttpClient();
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            RequestUri = new Uri($"https://api.metadefender.com/v4/hash/{hash}"),
            Headers =
            {
                { "apikey", apiKey }
            }
        };
        using (var response = await client.SendAsync(request))
        {
            //If the hash isn't found we upload the file and then poll the API using the data_id
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound) { 
                var dataId = await UploadFile(apiKey, filePath);
                await PollScanResults(apiKey, dataId, hash);
            }
            else //If the hash is found we print the results to the console
            {
                response.EnsureSuccessStatusCode();
                var responseBody = JObject.Parse(await response.Content.ReadAsStringAsync());
                Console.WriteLine("Filename: " + responseBody["file_info"]["display_name"]);
                Console.WriteLine("OverallStatus: " + responseBody["process_info"]["result"]);

                var scanResults = responseBody["scan_results"]["scan_details"];
                
                //Printing the relevant data for each engine
                foreach (JProperty engine in scanResults)
                {
                    var details = engine.Value;
                    
                    string threatFound = details["threat_found"]?.ToString();
                    int scanResult = (int)details["scan_result_i"];
                    string defTime = details["def_time"]?.ToString();
                    
                    Console.WriteLine($"Engine: {engine.Name}");
                    if(threatFound == "")
                        Console.WriteLine($"Threat Found: Clean");
                    else
                        Console.WriteLine($"Threat Found: {threatFound}");
                    Console.WriteLine($"Scan Result: {scanResult}");
                    Console.WriteLine($"DefTime: {defTime}");
                    Console.WriteLine();
                }
            }
            
        }
    }
    
    //This function uploads the file and returns a data_id
    static async Task<string> UploadFile(string apiKey, string filePath)
    {
        var client = new HttpClient();
        var requestContent = new MultipartFormDataContent();
        
        using (var fileStream = File.OpenRead(filePath))
        using (var content = new StreamContent(fileStream))
        {
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            requestContent.Add(content, "file", Path.GetFileName(filePath));
            
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://api.metadefender.com/v4/file"),
                Headers = { { "apikey", apiKey } },
                Content = requestContent
            };


            using (var response = await client.SendAsync(request))
            {
                response.EnsureSuccessStatusCode();
                var responseBody = await response.Content.ReadAsStringAsync();

                var responseBodyJson = JObject.Parse(responseBody);
                string dataId = responseBodyJson["data_id"]?.ToString();
                
                return dataId;
            }
        }
    }
    
    //This function polls the api for the result using data_id every 10 seconds until a result is received
    static async Task PollScanResults(string apiKey, string dataId, string hash)
    {
        var client = new HttpClient();
        var url = $"https://api.metadefender.com/v4/file/{dataId}";

        bool isComplete = false;
        while (!isComplete)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("apikey", apiKey);

            using (var response = await client.SendAsync(request))
            {
                response.EnsureSuccessStatusCode();
                var responseBody = await response.Content.ReadAsStringAsync();
                var json = JObject.Parse(responseBody);

                var progressPercentage = json["scan_results"]["progress_percentage"]?.ToString();

                if (progressPercentage == "100")
                {
                    isComplete = true;
                    await PerformHashLookup(apiKey,hash);
                }
                else
                {
                    await Task.Delay(10000); // Wait for 10 seconds before polling again
                }
            }
        }
    }

}
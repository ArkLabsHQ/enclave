using System;
using System.Net;
using System.Text;

// commit2: uncomment and add Newtonsoft.Json to .csproj
// using Newtonsoft.Json;

class Program
{
    static void Main(string[] args)
    {
        var port = Environment.GetEnvironmentVariable("ENCLAVE_APP_PORT") ?? "7074";
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://+:{port}/");
        listener.Start();
        Console.WriteLine($"listening on :{port}");

        while (true)
        {
            var ctx = listener.GetContext();
            var body = Encoding.UTF8.GetBytes("{\"status\":\"ok\"}");
            ctx.Response.ContentType = "application/json";
            ctx.Response.OutputStream.Write(body, 0, body.Length);
            ctx.Response.Close();
        }
    }
}

using System;
using System.Net;
using System.Text;
using Newtonsoft.Json;

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
            var response = new { status = "ok" };
            var json = JsonConvert.SerializeObject(response);
            var body = Encoding.UTF8.GetBytes(json);
            ctx.Response.ContentType = "application/json";
            ctx.Response.OutputStream.Write(body, 0, body.Length);
            ctx.Response.Close();
        }
    }
}

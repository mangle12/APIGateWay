using APIGateWay.Interface;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;
using Ocelot.Logging;
using Ocelot.Middleware;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace APIGateWay.Middleware
{
    public class ResponseMiddleware : OcelotMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IJWTService _jwtservice;

        public ResponseMiddleware(RequestDelegate next, IOcelotLoggerFactory loggerFactory, IJWTService jwtservice) : base(loggerFactory.CreateLogger<ResponseMiddleware>())
        {
            _next = next;
            _jwtservice = jwtservice;            
        }

        public async Task Invoke(HttpContext context)
        {
            var errors = context.Items.Errors();

            if (errors.Count == 0 && context.Request.Method.ToUpper() != "OPTIONS")
            {
                //登入api
                if (context.Request.Path == "/user/login")
                {
                    var downstreamRoute = context.Items.DownstreamResponse();

                    //取token並塞到body中                                        
                    if (context.Response != null)
                    {
                        var result = await downstreamRoute.Content.ReadAsStringAsync();

                        JObject data = JObject.Parse(result);

                        //登入者ID
                        var loginId = data["data"][0]["user_account"].ToString();

                        string token = _jwtservice.GetToken_1(loginId);

                        string access_token = $",\"access_token\":\"{token}\"";

                        //access_token寫入body
                        result = result.Insert(result.Length - 1, access_token);

                        var downstreamResponse = new DownstreamResponse(new StringContent(result, Encoding.UTF8, "application/json"), context.Items.DownstreamResponse().StatusCode, context.Items.DownstreamResponse().Headers, context.Items.DownstreamResponse().ReasonPhrase);

                        context.Items.UpsertDownstreamResponse(downstreamResponse);
                    }
                }
                else
                {
                    await _next.Invoke(context);
                }
            }
        }
    }
}

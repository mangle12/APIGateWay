using APIGateWay.Interface;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIGateWay.Middleware
{
    public class JWTTokenMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IJWTService _jwtservice;

        public JWTTokenMiddleware(RequestDelegate next, IJWTService jwtservice)
        {
            _next = next;
            _jwtservice = jwtservice;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            //https://jwt.io/
            string account = "0028415";
            string token = _jwtservice.GetToken_1(account);


            await _next(context);


        }
    }
}

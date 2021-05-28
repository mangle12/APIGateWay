using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Ocelot.Logging;
using Ocelot.Middleware;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace APIGateWay.Middleware
{
    public class ApiPermission
    {
        public string AllowedRoles { get; set; }

        public string PathPattern { get; set; }

        public string Method { get; set; }
    }

    public class UrlBasedAuthenticationMiddleware : OcelotMiddleware
    {
        private readonly RequestDelegate _next;        

        public UrlBasedAuthenticationMiddleware(RequestDelegate next, IOcelotLoggerFactory loggerFactory) : base(loggerFactory.CreateLogger<UrlBasedAuthenticationMiddleware>())
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            //Token 白名單
            var permissions = new[]
            {
               new ApiPermission()
               {
                   PathPattern = "/todo",
                   Method = "GET",
                   AllowedRoles = ""
               },
               new ApiPermission()
               {
                   PathPattern = "/user/login",
                   Method = "POST",
                   AllowedRoles = ""
               }
            };

            var downstreamRoute = context.Items.DownstreamRoute();

            var result = await context.AuthenticateAsync(downstreamRoute.AuthenticationOptions.AuthenticationProviderKey);
            context.User = result.Principal;

            var user = context.User;
            var request = context.Request;

            var permission = permissions.FirstOrDefault(p =>
                                                        request.Path.Value.Equals(p.PathPattern, StringComparison.OrdinalIgnoreCase) && p.Method.ToUpper() == request.Method.ToUpper());

            //if (permission == null)// 完全匹配不到，再根據正則匹配
            //{
            //    permission = permissions.FirstOrDefault(p =>
            //                                   Regex.IsMatch(request.Path.Value, p.PathPattern, RegexOptions.IgnoreCase) && p.Method.ToUpper() == request.Method.ToUpper());
            //}

            if (!user.Identity.IsAuthenticated)
            {
                //沒帶Token
                if (permission != null && string.IsNullOrWhiteSpace(permission.AllowedRoles)) //默認需要登錄才能訪問
                {
                    //context.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "Anonymous") }, context.DownstreamReRoute.AuthenticationOptions.AuthenticationProviderKey));
                }
                else
                {
                    //SetPipelineError(context, new UnauthenticatedError("unauthorized, need login"));
                    context.Response.Clear();
                    context.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
                    await context.Response.WriteAsync("Unauthorized");
                    return;
                }
            }
            else
            {
                //有帶Token
                if (!string.IsNullOrWhiteSpace(permission?.AllowedRoles) && !permission.AllowedRoles.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Any(r => user.IsInRole(r)))
                {
                    //SetPipelineError(context, new UnauthorisedError("forbidden, have no permission"));
                    context.Response.Clear();
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    await context.Response.WriteAsync("Token Fail");
                    return;
                }
            }

            await _next.Invoke(context);
        }
    }
}

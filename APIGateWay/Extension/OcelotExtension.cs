using APIGateWay.Middleware;
using Microsoft.AspNetCore.Builder;

namespace APIGateWay.Extension
{
    public static class OcelotExtension
    {
        public static IApplicationBuilder UseResponseMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ResponseMiddleware>();
        }
    }
}

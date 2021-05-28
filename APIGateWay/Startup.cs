using APIGateWay.Interface;
using APIGateWay.Middleware;
using APIGateWay.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using System;
using System.Text;
using APIGateWay.Extension;
using Ocelot.Provider.Polly;

namespace APIGateWay
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            //取得appsettings.json內JwtToken Tag訊息
            var audienceConfig = Configuration.GetSection("JwtToken");
            //取得Secret
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(audienceConfig["Secret"]));

            //token 驗證參數集合
            var tokenValidationParameters = new TokenValidationParameters
            {
                //必須驗證密鑰
                ValidateIssuerSigningKey = true,
                //取值密鑰
                IssuerSigningKey = signingKey,
                //必須簽發人
                ValidateIssuer = true,
                //取值簽發人
                ValidIssuer = audienceConfig["Issuer"],
                //必須驗證觀眾
                ValidateAudience = true,
                //取值觀眾
                ValidAudience = audienceConfig["Audience"],
                //驗證Token是否過期，使用目前時間和Token內Claims中的NotBefore和Expires對比
                ValidateLifetime = true,
                //允許的伺服器時間偏移量
                ClockSkew = TimeSpan.Zero,
                //是否要求Token的Claims中必須包含Expires
                RequireExpirationTime = true,

                ValidAudiences = new[] { "todo" }
            };

            //檢查 HTTP Header 的 Authorization 是否有 JWT Bearer Token
            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = "IdentityApiKey";
            })
            //設定 JWT Bearer Token 的檢查選項
            .AddJwtBearer("IdentityApiKey", x =>
            {
                x.RequireHttpsMetadata = false;
                //在JwtBearerOptions配置中，IssuerSigningKey(簽名秘鑰)、ValidIssuer(Token頒發機構)、ValidAudience(頒發給誰)三個參數是必須的。
                x.TokenValidationParameters = tokenValidationParameters;
            });

            //services.AddOcelot(Configuration)//注入Ocelot服務
            services.AddOcelot(Configuration).AddPolly();//如果有啟用熔斷則需增加AddPolly()

            services.AddSingleton<IJWTService, JWTService>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            //紀錄Requset & Response header和body
            app.UseMiddleware<AuthenticationMiddleware>();

            //使用驗證權限的 Middleware
            //app.UseAuthentication();

            //app.UseOcelot().Wait();//使用Ocelot套件
            app.UseOcelot((build, config) =>
            {
                build.BuildCustomeOcelotPipeline(config);
            }).Wait();

            app.UseHttpsRedirection();

            app.UseRouting();

            //啟用授權功能
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

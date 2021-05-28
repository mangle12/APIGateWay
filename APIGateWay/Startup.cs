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

            //���oappsettings.json��JwtToken Tag�T��
            var audienceConfig = Configuration.GetSection("JwtToken");
            //���oSecret
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(audienceConfig["Secret"]));

            //token ���ҰѼƶ��X
            var tokenValidationParameters = new TokenValidationParameters
            {
                //�������ұK�_
                ValidateIssuerSigningKey = true,
                //���ȱK�_
                IssuerSigningKey = signingKey,
                //����ñ�o�H
                ValidateIssuer = true,
                //����ñ�o�H
                ValidIssuer = audienceConfig["Issuer"],
                //���������[��
                ValidateAudience = true,
                //�����[��
                ValidAudience = audienceConfig["Audience"],
                //����Token�O�_�L���A�ϥΥثe�ɶ��MToken��Claims����NotBefore�MExpires���
                ValidateLifetime = true,
                //���\�����A���ɶ������q
                ClockSkew = TimeSpan.Zero,
                //�O�_�n�DToken��Claims�������]�tExpires
                RequireExpirationTime = true,

                ValidAudiences = new[] { "todo" }
            };

            //�ˬd HTTP Header �� Authorization �O�_�� JWT Bearer Token
            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = "IdentityApiKey";
            })
            //�]�w JWT Bearer Token ���ˬd�ﶵ
            .AddJwtBearer("IdentityApiKey", x =>
            {
                x.RequireHttpsMetadata = false;
                //�bJwtBearerOptions�t�m���AIssuerSigningKey(ñ�W���_)�BValidIssuer(Token�{�o���c)�BValidAudience(�{�o����)�T�ӰѼƬO�������C
                x.TokenValidationParameters = tokenValidationParameters;
            });

            //services.AddOcelot(Configuration)//�`�JOcelot�A��
            services.AddOcelot(Configuration).AddPolly();//�p�G���ҥκ��_�h�ݼW�[AddPolly()

            services.AddSingleton<IJWTService, JWTService>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            //����Requset & Response header�Mbody
            app.UseMiddleware<AuthenticationMiddleware>();

            //�ϥ������v���� Middleware
            //app.UseAuthentication();

            //app.UseOcelot().Wait();//�ϥ�Ocelot�M��
            app.UseOcelot((build, config) =>
            {
                build.BuildCustomeOcelotPipeline(config);
            }).Wait();

            app.UseHttpsRedirection();

            app.UseRouting();

            //�ҥα��v�\��
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

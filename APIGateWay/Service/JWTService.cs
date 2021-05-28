using APIGateWay.Interface;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace APIGateWay.Service
{
    public class JWTService : IJWTService
    {
        private readonly IConfiguration _config;

        public JWTService(IConfiguration configuration)
        {
            _config = configuration;
        }

        /// <summary>
        /// 產生Token
        /// </summary>
        /// <param name="account">使用者帳號</param>
        /// <returns>Token</returns>
        public string GetToken(string account)
        {
            // STEP0: 在產生 JWT Token 之前，可以依需求做身分驗證

            // STEP1: 建立使用者的 Claims 聲明，這會是 JWT Payload 的一部分
            var userClaims = new ClaimsIdentity(new[] {
                new Claim(JwtRegisteredClaimNames.NameId, account),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("CustomClaim", "Anything You Like")
            });

            // STEP2: 取得對稱式加密 JWT Signature 的金鑰
            // 這部分是選用，但此範例在 Startup.cs 中有設定 ValidateIssuerSigningKey = true 所以這裡必填
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtToken:Secret"]));
            // STEP3: 建立 JWT TokenHandler 以及用於描述 JWT 的 TokenDescriptor
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _config["JwtToken:Issuer"],
                Audience = _config["JwtToken:Issuer"],
                Subject = userClaims,
                Expires = DateTime.Now.AddMinutes(30),//過期時間
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
            };
            // 產出所需要的 JWT Token 物件
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            // 產出序列化的 JWT Token 字串
            var serializeToken = tokenHandler.WriteToken(securityToken);

            return serializeToken;
        }

        public Guid ValidateToken(string token)
        {
            var principal = GetPrincipal(token);
            if (principal == null)
            {
                return Guid.Empty;
            }

            ClaimsIdentity identity;
            try
            {
                identity = (ClaimsIdentity)principal.Identity;
            }
            catch (NullReferenceException)
            {
                return Guid.Empty;
            }
            var userIdClaim = identity.FindFirst("userId");
            var userId = new Guid(userIdClaim.Value);
            return userId;
        }

        private ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (jwtToken == null)
                {
                    return null;
                }
                var key = Encoding.UTF8.GetBytes(_config["JwtToken:Secret"]);
                var parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
                IdentityModelEventSource.ShowPII = true;
                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token,
                        parameters, out securityToken);
                return principal;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// 產生Token_1
        /// </summary>
        /// <param name="account">使用者帳號</param>
        /// <returns>Token</returns>
        public string GetToken_1(string account)
        {
            var now = DateTime.UtcNow;

            //建立使用者的 Claims 聲明，這會是 JWT Payload 的一部分
            var claims = new Claim[]
            {
                //jwt所面向的用戶
                new Claim(JwtRegisteredClaimNames.Sub, account),
                //jwt的唯一身份標識，主要用來作為一次性token,從而迴避重放攻擊
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                //jwt的簽發時間
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUniversalTime().ToString(), ClaimValueTypes.Integer64)
            };

            //下面使用 Microsoft.IdentityModel.Tokens來建立 JwtToken

            //密鑰
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtToken:Secret"]));

            var jwt = new JwtSecurityToken(
                //jwt簽發人
                issuer: _config["JwtToken:Issuer"],
                //jwt觀眾
                audience: _config["JwtToken:Audience"],
                //Claims 聲明
                claims: claims,
                //定義在什麼時間之前，該jwt都是不可用的
                notBefore: now,
                //jwt過期時間
                expires: now.Add(TimeSpan.FromDays(1)),
                //签名凭证: 安全密钥、签名算法
                signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
            );
            //產生jwt Token
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return encodedJwt;
        }
    }
}

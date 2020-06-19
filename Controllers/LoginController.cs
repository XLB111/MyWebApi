using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace MyWeb.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController( IConfiguration configuration)
        {
            this._configuration = configuration;
        }
        [AllowAnonymous]
        [HttpGet]
        [Route("api/nopermission")]
        public IActionResult NoPermission()
        {
            return Forbid("No Permission!");
        }
        /// <summary>
        /// login
        /// </summary>
        [AllowAnonymous]
        [HttpGet]
        [Route("api/auth")]
        public IActionResult Get(string userName, string pwd)
        {
            if (CheckAccount(userName, pwd, out string role))
            {
                string ValidAudience = userName + pwd + DateTime.Now.ToString();
                // push the user’s name into a claim, so we can identify the user later on.
                //这里可以随意加入自定义的参数，key可以自己随便起
                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Nbf,$"{new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()}") ,
                    new Claim (JwtRegisteredClaimNames.Exp,$"{new DateTimeOffset(DateTime.Now.AddMinutes(30)).ToUnixTimeSeconds()}"),
                    new Claim(ClaimTypes.NameIdentifier, userName),
                    new Claim("Role", role)
                };
                //sign the token using a secret key.This secret will be shared between your API and anything that needs to check that the token is legit.
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecurityKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                //.NET Core’s JwtSecurityToken class takes on the heavy lifting and actually creates the token.
                var token = new JwtSecurityToken(
                    issuer: "XLB", //颁发者
                    audience: ValidAudience,//过期时间
                    expires: DateTime.Now.AddMinutes(30),// 签名证书
                    signingCredentials: creds, //自定义参数
                    claims: claims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }
            else
            {
                return BadRequest(new { message = "username or password is incorrect." });
            }
        }
        /// <summary>
        /// 模拟登陆校验
        /// </summary>
        private bool CheckAccount(string userName, string pwd, out string role)
        {
            role = "user";
            if (string.IsNullOrEmpty(userName))
                return false;
            if (userName.Equals("admin"))
                role = "admin";
            return true;
        }

        // GET api/values1
        [HttpGet]
        [Route("api/value1")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value1" };
        }
        // GET api/values2
        /**
         * 该接口用Authorize特性做了权限校验，如果没有通过权限校验，则http返回状态码为401
         */
        [HttpGet]
        [Route("api/value2")]
        [Authorize]
        public ActionResult<IEnumerable<string>> Get2()
        {
            var auth = HttpContext.AuthenticateAsync().Result.Principal.Claims;
            var userName = auth.FirstOrDefault(t => t.Type.Equals(ClaimTypes.NameIdentifier))?.Value;
            return new string[] { "这个接口登陆过的都能访问", $"userName={userName}" };
        }
        /**
         * 这个接口必须用admin
         **/
        [HttpGet]
        [Route("api/value3")]
        [Authorize("Permission")]
        public ActionResult<IEnumerable<string>> Get3()
        {
            //这是获取自定义参数的方法
            var auth = HttpContext.AuthenticateAsync().Result.Principal.Claims;
            var userName = auth.FirstOrDefault(t => t.Type.Equals(ClaimTypes.NameIdentifier))?.Value;
            var role = auth.FirstOrDefault(t => t.Type.Equals("Role"))?.Value;
            return new string[] { "这个接口有管理员权限才可以访问", $"userName={userName}", $"Role={role}" };
        }

    }
}

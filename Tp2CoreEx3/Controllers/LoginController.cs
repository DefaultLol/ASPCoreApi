using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Tp2CoreEx3.Model;

namespace Tp2CoreEx3.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public LoginController(IConfiguration config)
        {
            _configuration = config;
        }

        private readonly IEnumerable<User> _users = new List<User>
        {
            new User {Id="1", Username="tarik", Password="123", Role="admin"},
            new User {Id="2", Username="ayoub", Password="123", Role="user"},
        };

        private string GenerateJSONWebToken(User userInfo)
        {
            var user = _users.Where(x => x.Username == userInfo.Username && x.Password == userInfo.Password).SingleOrDefault();
            if (user == null)
            {
                return null;
            }
            byte[] data = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
            string b64 = Convert.ToBase64String(data);
            var signingKey = Convert.FromBase64String(b64);
            var expirationDuration = int.Parse(_configuration["Jwt:ExpiryDuration"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = null,
                Audience = null,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(expirationDuration),
                Subject = new System.Security.Claims.ClaimsIdentity(new List<Claim>
                {
                    new Claim("userId",user.Id.ToString()),
                    new Claim(ClaimTypes.Role,user.Role),
                    new Claim("Usernames",user.Username.ToString()),
                }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtTokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            var token = jwtTokenHandler.WriteToken(jwtToken);

            return token;
        }

        [HttpPost]
        [Route("/api/login/login2")]
        public IActionResult Post([FromBody] User user)
        {
            var jwtToken = GenerateJSONWebToken(user);
            if (jwtToken == null)
            {
                return StatusCode(401, "My error message");
            }
            List<string> tokenList = new List<string>();
            tokenList.Add(jwtToken);
            return Ok(tokenList);
        }

        

        [HttpGet]
        [Authorize]
        [Route("/api/login")]
        public IActionResult Get()
        {
            var currentUser = HttpContext.User.Claims.Where(x => x.Type == "userId").SingleOrDefault();
            var name = HttpContext.User.Claims.Where(x => x.Type == "Usernames").SingleOrDefault();
            var role = HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Role).SingleOrDefault();
            string text = "userId : " + currentUser + " , username : " + name;
            User user = new User()
            {
                Id = currentUser.ToString(),
                Username = name.Value.ToString(),
                Role = role.Value.ToString()
            };
            return Ok(user);
        }

        [HttpGet]
        [Authorize(Roles ="admin")]
        [Route("/api/login/gestion")]
        public IActionResult Gestion()
        {
            var currentUser = HttpContext.User.Claims.Where(x => x.Type == "userId").SingleOrDefault();
            var name = HttpContext.User.Claims.Where(x => x.Type == "Usernames").SingleOrDefault();
            var role = HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Role).SingleOrDefault();
            string text = "userId : " + currentUser + " , username : " + name;
            User user = new User()
            {
                Id = currentUser.ToString(),
                Username = name.Value.ToString(),
                Role = role.Value.ToString()
            };
            return Ok(user);
        }
    }
}

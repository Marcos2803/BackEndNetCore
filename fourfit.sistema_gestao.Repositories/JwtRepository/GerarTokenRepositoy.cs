using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace fourfit.sistema_gestao.Repositories.JwtRepository
{
    public class GerarTokenRepositoy : IAuthenticationJwtServices
    {
        private readonly IConfiguration _config;

        public GerarTokenRepositoy(IConfiguration config)
        {
            _config = config;
        }
        public string CreateToken(User user)
        {
            var secret = Encoding.ASCII.GetBytes(_config.GetSection("JwtConfiguration:Secret").Value);
            var symmetricSecuriryKey = new SymmetricSecurityKey(secret);

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, $"{user.PrimeiroNome.ToString()} {user.SobreNome.ToString()}"),
                    new Claim(ClaimTypes.Email, user.Email.ToString())
                }),

                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(symmetricSecuriryKey, SecurityAlgorithms.HmacSha256Signature)


            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenGenerated = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(tokenGenerated);
            return token;

        }
    }
}

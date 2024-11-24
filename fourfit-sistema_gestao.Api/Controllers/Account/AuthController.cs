using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Account;
using fourfit_sistema_gestao.Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using System.IdentityModel.Tokens.Jwt;

namespace fourfit_sistema_gestao.Api.Controllers.Account
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<User> _signInManager;
        private readonly IUserClaimsPrincipalFactory<User> _userClaimsPrincipalFactory;
        private readonly UserManager<User> _userManager;
        private readonly IAuthenticationJwtServices _authenticationJwtServices;

        public AuthController(SignInManager<User> signInManager,
            IUserClaimsPrincipalFactory<User> userClaimsPrincipalFactory,
            UserManager<User> userManager,
            IAuthenticationJwtServices authenticationJwtServices
            )
        {
            _signInManager = signInManager;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            _userManager = userManager;
            _authenticationJwtServices = authenticationJwtServices;
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(RegisterViewModels model)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(model.Email);
                if (user == null)
                {

                    user = new User
                    {
                        Id = Guid.NewGuid().ToString(),
                        PrimeiroNome = model.PrimeiroNome,
                        SobreNome = model.SobreNome,
                        Email = model.Email,
                        UserName = model.Email,
                        PasswordHash = model.Password,
                        Celular = model.Celular,
                    };

                    if (model.Password != model.PasswordConfirmn)
                        return BadRequest("Senhas não conferem");

                    var resultado = await _userManager.CreateAsync(user, model.Password);

                    if (resultado.Succeeded)
                    {

                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                        
                        var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { token = token, email = model.Email }, Request.Scheme);

                        var mail = new EmailServices(); 
                        var msg = new EmailAddressViewModel()
                        {
                            Subject = "E-mail de confirmação de conta",
                            To = model.Email,
                            Body = confirmationLink 
                        };      
                        await mail.SendEmailAsync(msg);

                    }
                    else
                    {
                        foreach (var erro in resultado.Errors)
                        {
                            return BadRequest(erro.Description);
                        }
                    }
                    return Ok($"Usuário {model.PrimeiroNome} cadastrado com sucesso! Verifique seu e-mail para ativar a conta.");
                }
                else
                {
                    return BadRequest("Usuário já existe!");
                }
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                return BadRequest("Token ou e-mail inválidos.");
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest("Usuário não encontrado.");
            }

            var resultado = await _userManager.ConfirmEmailAsync(user, token);
            if (resultado.Succeeded)
            {
                return Ok("E-mail confirmado com sucesso!");
            }
            else
            {
                return BadRequest("Falha ao confirmar o e-mail.");
            }
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            try
            {
                if (string.IsNullOrEmpty(model.UserName) && string.IsNullOrEmpty(model.Password))
                {
                    return Unauthorized("Campos são obrigatórios");
                }


                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user != null && !await _userManager.IsLockedOutAsync(user))
                {
                    if (await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        if (!await _userManager.IsEmailConfirmedAsync(user))
                        {
                            return BadRequest("Conta em processo de autorização.");

                        }

                        // DEU TUDO CERTO
                        var userCurrent = await _userManager.FindByEmailAsync(model.UserName);
                        await _userManager.ResetAccessFailedCountAsync(user);
                        var principal = await _userClaimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, new System.Security.Claims.ClaimsPrincipal(principal));


                        var token = _authenticationJwtServices.CreateToken(userCurrent);
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var jsonToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
                        return Ok(new {
                         token = token,
                         TokenEspiraEm = jsonToken?.ValidTo,
                         Name = userCurrent.PrimeiroNome + " " + userCurrent.SobreNome
                        });

                    }

                    else
                    {
                        return BadRequest("Senha incorreta.");
                    }
                }
                else
                {
                    return BadRequest("Usuário não existe.");
                }







            }

            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("ForgotPassword")]
        [SwaggerResponse(statusCode: 200, description: "E-mail enviado para redefinição de senha")]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios")]
        [SwaggerResponse(statusCode: 500, description: "Erro interno")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return BadRequest("Usuário não encontrado.");
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetUrl = Url.Action("ResetPassword", "Auth", new { token = token, email = model.Email }, Request.Scheme);
                System.IO.File.WriteAllText("resetLinkToNewPass.txt", resetUrl);

                var mail = new EmailServices();
                var msg = new EmailAddressViewModel()
                {
                    Subject = "E-mail enviado para alteração de senha",
                    To = model.Email,
                    Body = resetUrl
                };

                await mail.SendEmailAsync(msg);

                return Ok("E-mail enviado com sucesso.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ops, ocorreu um erro: {ex.Message}");
            }
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ResetPassword")]
        [SwaggerResponse(statusCode: 200, description: "Página de redefinição de senha", Type = typeof(ResetPasswordViewModel))]
        public IActionResult ResetPassword(string token, string email)
        {
            return Ok(new ResetPasswordViewModel { Token = token, Email = email });
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("ResetPassword")]
        [SwaggerResponse(statusCode: 200, description: "Senha redefinida com sucesso")]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios")]
        [SwaggerResponse(statusCode: 500, description: "Erro interno")]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return BadRequest("Usuário não encontrado.");
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                if (!result.Succeeded)
                {
                    var errors = result.Errors.Select(e => e.Description).ToList();
                    return BadRequest(errors);
                }

                return Ok("Senha redefinida com sucesso.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ops, ocorreu um erro: {ex.Message}");
            }
        }


    }
}

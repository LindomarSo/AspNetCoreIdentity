using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using WebApp.Identity.Models;

namespace WebApp.Identity.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<MyUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<MyUser> _userClaimsPrincipal;
        private readonly SignInManager<MyUser> _signInManager;

        public HomeController(UserManager<MyUser> userManager,
                             IUserClaimsPrincipalFactory<MyUser> userClaimsPrincipal,
                             SignInManager<MyUser> signInManager)
        {
            _userManager = userManager;
            _userClaimsPrincipal = userClaimsPrincipal;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(loginModel.UserName);

                if(user != null && !await _userManager.IsLockedOutAsync(user))
                {
                    if(await _userManager.CheckPasswordAsync(user, loginModel.Password))
                    {
                        if(!await _userManager.IsEmailConfirmedAsync(user))
                        {
                            ModelState.AddModelError("" ,"Email não foi confirmado");
                            return View();
                        }

                        // Reseta a contagem para bloquear usuário 
                        await _userManager.ResetAccessFailedCountAsync(user);

                        // Two Factor 
                        if(await _userManager.GetTwoFactorEnabledAsync(user))
                        {
                           // Desenvolver o tokem que é mandado para o email 
                            var validator = await _userManager.GetValidTwoFactorProvidersAsync(user);

                            if(validator.Contains("Email"))
                            {
                                // Gera o token 
                                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                                // Aciona o servidor para enviar o email 
                                System.IO.File.WriteAllText("TwoFactor.txt", token);

                                await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                                    Store2FA(user.Id, "Email")
                                );

                                return RedirectToAction("TwoFactor");
                            }
                        }

                        // Cria as claims 
                        var principal = await _userClaimsPrincipal.CreateAsync(user);

                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

                    // Esta parte é desenvolida com signIn subustituindo o código acima
                        /*
                        var signInResult = await _signInManager.PasswordSignInAsync(
                                                                                    loginModel.UserName, 
                                                                                    loginModel.Password,
                                                                                    false,
                                                                                    false);

                        if(signInResult.Succeeded)
                        {
                            return RedirectToAction("About");
                        }
                        */

                        return RedirectToAction("About");
                    }

                    // Conta as falhas do usuário 
                    await _userManager.AccessFailedAsync(user);

                    if(await _userManager.IsLockedOutAsync(user))
                    {
                        // Email deve ser enviado com sugestão de mudança de senha!
                    }
                }
                ModelState.AddModelError("", "Usuário ou senha inválido");
            }

            return View();
        }

        public ClaimsPrincipal Store2FA(string userId, string provider)
        {
            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim("sub", userId),
                new Claim("amr", provider)
            }, IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View("Login");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel forgotPassword)
        {
            if(ModelState.IsValid)
            {
                var user  = await _userManager.FindByEmailAsync(forgotPassword.Email);

                if(user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetURL = Url.Action("ResetPassword", "Home", 
                                                new { token = token, email = forgotPassword.Email }, Request.Scheme);

                    // Servidor de envio de email
                    System.IO.File.WriteAllText("ResetTextLink", resetURL);

                    return View("Success");
                }
                else
                {
                    // Email não foi encontrado
                    ModelState.AddModelError("","Email não encontrado.");
                }
            }
            return View();
        }

        /// <summary>
        /// Reset senha 
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public IActionResult ResetPassword(string token,  string email)
        {
            return View(new ResetPasswordModel { Token = token, Email = email });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPassword)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(resetPassword.Email);

                if(user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                    if(!result.Succeeded)
                    {
                        foreach(var erro in result.Errors)
                        {
                            ModelState.AddModelError(erro.Code, erro.Description);
                        }

                        return View();
                    }

                    return View("Success");
                }

                ModelState.AddModelError("", "Inválid request");
            }
            return View();
        }

        [HttpGet]
        [Authorize]
        public IActionResult About()
        {
            return View(); 
        }

        [HttpGet]
        public IActionResult Success()
        {
            return View();
        }

        /// <summary>
        /// Register
        /// </summary>
        /// <param name="registerModel"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel registerModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(registerModel.UserName);

                if(user is null)
                {
                    user = new MyUser
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = registerModel.UserName,
                        Email = registerModel.UserName
                    };

                    var result = await _userManager.CreateAsync(user, registerModel.Password);

                    if(result.Succeeded)
                    {
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "Home",  
                        new { token = token, email = user.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("ConfirmEmail.txt", confirmationEmail);

                        return View("Success");
                    }
                    else
                    {
                        foreach(var erro in result.Errors)
                        {
                            ModelState.AddModelError("", erro.Description);
                        }

                        return View();
                    }
                }

                return View("Success");
            }

            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        /// <summary>
        /// Confirme Email
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public async Task<IActionResult> ConfirmEmailAddress(string token, string email)
        {
            var user =  await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if(result.Succeeded)
                {
                    return View("Success");
                }
            }
            return View("Error");
        }

        [HttpPost]
        public IActionResult ConfirmEmailAddress()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFactorModel twoFactor)
        {
            // Usado para validar se o token expirou 
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);

            if(!result.Succeeded)
            {
                // Expirou o token 
                ModelState.AddModelError("", "Seu token expirou.");

                return View();
            }

            if(ModelState.IsValid)
            {
                // procura o usuário pelo id que está nas claims 
                var user = await _userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));

                if(user != null)
                {
                    // Verfica se o usuário encontrado corresponde ao usuário das claims
                    var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, 
                        result.Principal.FindFirstValue("amr"), twoFactor.Token
                    );

                    if(isValid)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
                        var claimsPrincipal = await _userClaimsPrincipal.CreateAsync(user);
                        
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

                        // await _userManager.SetTwoFactorEnabledAsync(user, false);

                        return RedirectToAction("About");
                    }

                    ModelState.AddModelError("", "Token inválido");
                    return View();
                }
                
                ModelState.AddModelError(" ", "Inválid Request");
            }
            return View();
        }

        [HttpGet]
        public IActionResult TwoFactor()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

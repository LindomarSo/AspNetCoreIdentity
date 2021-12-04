using System.ComponentModel.DataAnnotations;

namespace WebApp.Identity.Models
{
    public class TwoFactorModel
    {
        [Required]
        public string Token { get; set; }
    }
}
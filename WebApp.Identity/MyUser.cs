using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace WebApp.Identity
{
    public class MyUser : IdentityUser
    {
        public string NomeCompleto { get; set; }
        public string Member { get; set; } = "Member";
        public string OrgId { get; set; }
    }

    public class Organization
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }
}

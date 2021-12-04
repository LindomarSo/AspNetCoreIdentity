using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApp.Identity
{
    public class EntityContext : IdentityDbContext<MyUser>
    {
        public EntityContext(DbContextOptions<EntityContext> options) 
            : base(options) { } 

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Organization>(org => 
            {
                org.ToTable("Organizations");

                org.HasKey(x => x.Id);

                org.HasMany<MyUser>()
                    .WithOne()
                    .HasForeignKey(user => user.OrgId)
                    .IsRequired(false);
            });
        }
    }
}
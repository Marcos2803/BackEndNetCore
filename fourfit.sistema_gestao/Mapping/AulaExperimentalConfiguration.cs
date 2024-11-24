
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class AulaExperimentalConfiguration : IEntityTypeConfiguration<AulaExperimental>
    {
        public void Configure(EntityTypeBuilder<AulaExperimental> builder)
        {
            builder.ToTable("AulaExperimental");
            builder.HasKey("Id");

            builder.HasOne(x => x.User)
               .WithMany(a => a.AulaExperimental)
               .HasForeignKey(a => a.UserId);

            builder.HasOne(x => x.Horarios)
               .WithMany(a => a.AulaExperimental)
               .HasForeignKey(a => a.HorariosId);

            builder.Property(x => x.DataHExperimental)
              .HasColumnType("date")
              .IsRequired();

        }
    }
}

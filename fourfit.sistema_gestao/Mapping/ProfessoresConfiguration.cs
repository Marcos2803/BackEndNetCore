using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class ProfessoresConfiguration : IEntityTypeConfiguration<EntidadeProfessores>
    {
        public void Configure(EntityTypeBuilder<EntidadeProfessores> builder)
        {
            builder.ToTable("Professores");
            builder.HasKey("Id");

            builder.HasOne(x => x.User)
                .WithMany(a => a.Professores)
                .HasForeignKey(a => a.UserId);

            builder.Property(x => x.Cref)
              .HasColumnType("varchar(15)")
              .IsRequired();

            builder.Property(x => x.Especialidade)
              .HasColumnType("varchar(50)")
              .IsRequired();

            builder.Property(x => x.DataCadastro)
            .HasColumnType("date")
            .IsRequired();

            builder.Property(x => x.Status)
           .HasColumnType("varchar(10)")
           .IsRequired();

            builder.Property(e => e.Foto)
                .HasColumnType("varbinary(max)")
                .IsRequired(false);

        }
    }
}

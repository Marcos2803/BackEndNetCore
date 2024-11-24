using fourfit.sistema_gestao.Domain.Entities.Profission;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class ColaboradoresConfiguration : IEntityTypeConfiguration<EntidadeColaboradores>
    {
        public void Configure(EntityTypeBuilder<EntidadeColaboradores> builder)
        {

            builder.ToTable("Colaboradores");
            builder.HasKey("Id");

            builder.HasOne(x => x.User)
                .WithMany(a => a.colaboradores)
                .HasForeignKey(a => a.UserId);

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

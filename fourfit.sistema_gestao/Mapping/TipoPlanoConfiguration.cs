using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;


namespace fourfit.sistema_gestao.Mapping
{
    public class TipoPlanoConfiguration : IEntityTypeConfiguration<TipoPlano>
    {
        public void Configure(EntityTypeBuilder<TipoPlano> builder)
        {
            builder.ToTable("TipoPlano");
            builder.HasKey("Id");

            builder.Property(x => x.StatusPlanos)
           .HasColumnType("varchar(10)")
           .IsRequired();

            builder.Property(x => x.NomePlano)
           .HasColumnType("varchar(70)")
           .IsRequired();

            builder.Property(x => x.Descricao)
           .HasColumnType("varchar(70)")
           .IsRequired();

            builder.Property(x => x.DiaPorSemana)
                .IsRequired();

            builder.Property(x => x.DuracaoMes)
                .IsRequired();

            builder.Property(x => x.DuracaoDia)
                .IsRequired();

            builder.Property(x => x.ValorPlano)
                .HasColumnType(" decimal(18, 2)")
                .IsRequired();
        }
    }
}

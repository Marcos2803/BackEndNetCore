using fourfit.sistema_gestao.Domain.Entities.Financas;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class ContasBancariasConfiguration : IEntityTypeConfiguration<ContasBancarias>
    {
        public void Configure(EntityTypeBuilder<ContasBancarias> builder)
        {
            builder.ToTable("ContasBancarias");
            builder.HasKey("Id");

            builder.Property(x => x.Bancos)
          .HasColumnType("varchar(50)")
          .IsRequired();

            builder.Property(x => x.Descricao)
          .HasColumnType("varchar(50)")
          .IsRequired();

            builder.Property(x => x.Status)
          .HasColumnType("varchar(10)")
          .IsRequired();
        }

    }
}

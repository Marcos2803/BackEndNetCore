

using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class ParcelasConfiguration : IEntityTypeConfiguration<Parcelas>
    {

        public void Configure(EntityTypeBuilder<Parcelas> builder)
        {
            builder.ToTable("ParcelaMensalidades");
            builder.HasKey("Id");

            builder.HasOne(x => x.Mensalidades)
                .WithMany(a => a.ParcelaMensalidades)
                .HasForeignKey(a => a.MensalidadesId);

            builder.Property(x => x.DataVencimento)
            .HasColumnType("date")
            .IsRequired();

            builder.Property(x => x.Valor)
              .HasColumnType(" decimal(18, 2)")
              .IsRequired();

            //builder.Property(x => x.DataVencimento)
            //   .HasColumnType("varchar(10)")
            //   .IsRequired();
        }
    }
}

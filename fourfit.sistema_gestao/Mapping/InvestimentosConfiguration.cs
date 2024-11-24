using fourfit.sistema_gestao.Domain.Entities.Financas;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class InvestimentosConfiguration : IEntityTypeConfiguration<Investimentos>
    {
        public void Configure(EntityTypeBuilder<Investimentos> builder)
        {
            builder.ToTable("Investimentos");
            builder.HasKey(x => x.Id);

            builder.HasOne(x => x.FormaPagamento)
               .WithMany(a => a.Investimentos)
               .HasForeignKey(a => a.FormaPagamentoId);

            builder.HasOne(x => x.ContasBancarias)
               .WithMany(a => a.Investimentos)
               .HasForeignKey(a => a.ContasBancariasId);

            builder.Property(x => x.Descricao)
            .HasColumnType("varchar(30)")
             .IsRequired();

            builder.Property(x => x.ValorInvestido)
             .HasColumnType(" decimal(18, 2)")
             .IsRequired();

            builder.Property(x => x.DataVencimento)
             .HasColumnType("date")
             .IsRequired();

            builder.Property(x => x.DataPagamento)
             .HasColumnType("date")
             .IsRequired();

            builder.Property(x => x.StatusPagamentos)
          .HasColumnType("varchar(10)")
          .IsRequired();

            builder.Property(x => x.Observacao)
                .HasColumnType("varchar(100)")
                .IsRequired();
        }
    }
}

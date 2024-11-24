using fourfit.sistema_gestao.Domain.Entities.Financas;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class TipoDespesasConfiguration : IEntityTypeConfiguration<TipoDespesas>
    {
        public void Configure(EntityTypeBuilder<TipoDespesas> builder)
        {
            builder.ToTable("TipoDespesas");
            builder.HasKey(x => x.Id);

            builder.HasOne(x => x.Impostos)
                .WithMany(a => a.TipoDespesas)
                .HasForeignKey(a => a.ImpostosId);


            builder.HasOne(x => x.Colaboradores)
                   .WithMany(a => a.TipoDespesas)
                   .HasForeignKey(a => a.ColaboradoresId);

            builder.HasOne(x => x.Fornecedores)
                   .WithMany(a => a.TipoDespesas)
                   .HasForeignKey(a => a.ColaboradoresId);
        }
    }
}

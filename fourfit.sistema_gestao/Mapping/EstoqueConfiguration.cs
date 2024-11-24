using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class EstoqueConfiguration : IEntityTypeConfiguration<Estoque>
    {
        public void Configure(EntityTypeBuilder<Estoque> builder)
        {
            builder.ToTable("ControleEstoque");
            builder.HasKey("Id");


            //builder.Property(x => x.QuantidadeEstoque)
            //    .IsRequired();

            //builder.Property(x => x.EstoqueMinimo)
            //    .IsRequired();
        }
    }
}

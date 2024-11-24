using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class VendasConfiguration : IEntityTypeConfiguration<Vendas>
    {
        public void Configure(EntityTypeBuilder<Vendas> builder)
        {
            builder.ToTable("Vendas");
            builder.HasKey("Id");


            builder.Property(x => x.DataVenda)
              .HasColumnType("date")
              .IsRequired();

            
        }
    }
}

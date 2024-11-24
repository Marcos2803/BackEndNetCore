using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;


namespace fourfit.sistema_gestao.Mapping
{
    public class VendaItensConfiguration : IEntityTypeConfiguration<VendaItens>
    {
        public void Configure(EntityTypeBuilder<VendaItens> builder)
        {
            builder.ToTable("VendaItens");
            builder.HasKey("Id");

            builder.HasOne(x => x.Vendas)
                .WithMany(a => a.VendaItens)
                .HasForeignKey(a => a.VendasId);

            builder.HasOne(x => x.Produtos)
                .WithMany(a => a.VendaItens)
                .HasForeignKey(a => a.ProdutosId);

            builder.Property(x => x.Quantidade)
              .HasColumnType("int")
              .IsRequired();
        }
    }
}

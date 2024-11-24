using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class ProdutosConfiguration : IEntityTypeConfiguration<Produtos>
    {

        public void Configure(EntityTypeBuilder<Produtos> builder)
        {
            builder.ToTable("Produtos");
            builder.HasKey("Id");

            builder.HasOne(x => x.Categorias)
                .WithMany(a => a.Produtos)
                .HasForeignKey(a => a.CategoriasId);

            builder.Property(x => x.NomeProduto)
              .HasColumnType("varchar(100)")
              .IsRequired();

            builder.Property(x => x.PrecoCusto)
            .IsRequired()
            .HasColumnType("decimal(18,2)");

            builder.Property(x => x.PrecoVenda)
                .IsRequired()
                .HasColumnType("decimal(18,2)");

            builder.Property(x => x.QuantidadeEstoque)
               .IsRequired();

            builder.Property(x => x.EstoqueMinimo)
                .IsRequired();
        }
    }
}

using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class CategoriasConfiguration : IEntityTypeConfiguration<Categorias>
    {
        public void Configure(EntityTypeBuilder<Categorias> builder)
        {
            builder.ToTable("Categorias");
            builder.HasKey("Id");

            builder.Property(x => x.NomeCategoria)
              .HasColumnType("varchar(50)")
              .IsRequired();
        }

    }
}

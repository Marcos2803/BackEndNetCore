using fourfit.sistema_gestao.Domain.Entities.Financas;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class ImpostosConfiguration : IEntityTypeConfiguration<Impostos>
    {
        public void Configure(EntityTypeBuilder<Impostos> builder)
        {
            builder.ToTable("Impostos");
            builder.HasKey("Id");

            builder.Property(x => x.NomeImposto)
             .HasColumnType("varchar(30)")
             .IsRequired();
        }

        
    }
}

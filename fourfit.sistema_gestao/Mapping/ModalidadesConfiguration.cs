using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;



namespace fourfit.sistema_gestao.Mapping
{
    public class ModalidadesConfiguration : IEntityTypeConfiguration<Modalidades>
    {
        public void Configure(EntityTypeBuilder<Modalidades> builder)
        {
            builder.ToTable("Modalidades");
            builder.HasKey("Id");

            builder.HasOne(x => x.Planos)
                .WithMany(a => a.Modalidades)
                .HasForeignKey(a => a.PlanosId);

            builder.Property(x => x.Descricao)
             .HasColumnType("varchar(50)")
             .IsRequired();

            builder.Property(x => x.Status)
             .HasColumnType("varchar(20)")
             .IsRequired();

            builder.Property(x => x.AceitaCheckin)
             .HasColumnType("varchar(10)")
             .IsRequired();





        }
    }
}

using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class AvaliacaoFisicaConfiguration : IEntityTypeConfiguration<AvaliacaoFisica>
    {
        public void Configure(EntityTypeBuilder<AvaliacaoFisica> builder)
        {
            builder.ToTable("AvaliacaoFisica");
            builder.HasKey(x => x.Id);

            builder.HasOne(x => x.Alunos)
                  .WithMany(a => a.AvaliacoesFisicas)
                  .HasForeignKey(a => a.AlunosId);

            builder.Property(x => x.DataAvaliacao)
           .HasColumnType("date")
           .IsRequired();

            builder.Property(x => x.Idade)
                .IsRequired();

            builder.Property(x => x.Altura)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Peso)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.PercentualGordura)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.MassaMagra)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.TaxaMetabolica)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.GorduraVisceral)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Imc)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.BicepsRelaxadoD)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.BicepsRelaxadoE)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.BicepsContraidoD)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.BicepsContraidoE)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.AntebracoD)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.AntebracoE)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Costa)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Peitoral)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Cintura)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Abdomen)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.Quadril)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.CoxaD)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.CoxaE)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.PanturrilhaD)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.PanturrilhaE)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

        }
    }

}   
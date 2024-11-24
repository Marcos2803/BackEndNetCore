using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    internal class ParqConfiguration : IEntityTypeConfiguration<Parq>
    {
        public void Configure(EntityTypeBuilder<Parq> builder)
        {
            builder.ToTable("Parq");
            builder.HasKey("Id");

            builder.HasOne(x => x.Alunos)
                .WithMany(a => a.Parq)
                .HasForeignKey(a => a.AlunoId);

            builder.Property(x => x.ProblemaCardiaco)
               .IsRequired();

            builder.Property(x => x.DorNoPeitoAoSeExercitar)
              .IsRequired();

            builder.Property(x => x.DesmaiaOuSenteTontura)
              .IsRequired();

            builder.Property(x => x.ProblemaOssosOuArticulacoes)
              .IsRequired();

            builder.Property(x => x.TomaMedicamentosPressaoCardiaco)
              .IsRequired();

            builder.Property(x => x.MotivoFisicoOuDeSaude)
              .IsRequired();

            builder.Property(x => x.DataPreenchimento)
             .HasColumnType("date")
             .IsRequired();


        }
    }
}



using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class PersonalRecordConfiguration : IEntityTypeConfiguration<PersonalRecord>
    {
        public void Configure(EntityTypeBuilder<PersonalRecord> builder)
        {
            builder.ToTable("PersonalRecord");
            builder.HasKey("Id");

            builder.HasOne(x => x.Alunos)
                .WithMany(a => a.PersonalRecord)
                .HasForeignKey(a => a.AlunosId);

            builder.HasOne(x => x.Exercicios)
                .WithMany(a => a.PersonalRecord)
                .HasForeignKey(a => a.ExerciciosId);

            builder.Property(x => x.PesoPR)
                .HasColumnType("decimal(5,2)")
                .IsRequired();

            builder.Property(x => x.DataPR)
            .HasColumnType("date")
            .IsRequired();

            builder.Property(x => x.Observacao)
            .HasColumnType("varchar(100)")
            .IsRequired();

        }
    }
}

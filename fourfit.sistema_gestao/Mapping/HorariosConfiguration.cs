using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class HorariosConfiguration : IEntityTypeConfiguration<Horarios>
    {
        public void Configure(EntityTypeBuilder<Horarios> builder)
        {
            builder.ToTable("Horarios");
            builder.HasKey("Id");

            builder.HasOne(x => x.Professores)
                .WithMany(a => a.Horarios)
                .HasForeignKey(a => a.ProfessoresId);

            builder.HasOne(x => x.Modalidades)
                .WithMany(a => a.Horarios)
                .HasForeignKey(a => a.ModalidadesId);

            builder.Property(x => x.Dia)
            .HasColumnType("varchar(14)")
             .IsRequired();

            builder.Property(x => x.HoraInicio)
            .HasColumnType("time")
            .IsRequired();

            builder.Property(x => x.HoraFim)
           .HasColumnType("time")
            .IsRequired();

            builder.Property(x => x.Descricao)
            .HasColumnType("varchar(255)")
            .IsRequired();

            builder.Property(x => x.LimiteAlunos)
                .IsRequired();

            builder.Property(x => x.Status)
           .HasColumnType("varchar(10)")
           .IsRequired();


        }
    }
}

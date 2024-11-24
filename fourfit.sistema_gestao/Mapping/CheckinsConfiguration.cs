using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class CheckinsConfiguration : IEntityTypeConfiguration<Checkins>
    {
        public void Configure(EntityTypeBuilder<Checkins> builder)
        {
            builder.ToTable("Checkins");
            builder.HasKey(x => x.Id);

            builder.HasOne(x => x.Alunos)
                 .WithMany(a => a.Checkins)
                 .HasForeignKey(a => a.AlunosId);

            builder.HasOne(x => x.Horarios)
                .WithMany(a => a.Checkins)
                .HasForeignKey(a => a.HorariosId);

            builder.Property(x => x.DataCheckin)
           .HasColumnType("date")
           .IsRequired();

        }
    }
}

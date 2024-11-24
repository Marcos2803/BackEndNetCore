using fourfit.sistema_gestao.Domain.Entities.Alunos;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace fourfit.sistema_gestao.Mapping
{
    public class AlunosConfiguration : IEntityTypeConfiguration<EntidadeAlunos>
    {
        public void Configure(EntityTypeBuilder<EntidadeAlunos> builder)
        {
            builder.ToTable("Alunos");
            builder.HasKey("Id");

            builder.HasOne(x => x.User)
                .WithMany(a => a.Alunos)
                .HasForeignKey(a => a.UserId);

            builder.Property(x => x.DataNacimento)
              .HasColumnType("date")
              .IsRequired();

            builder.Property(x => x.StatusAlunos)
           .HasColumnType("varchar(10)")
           .IsRequired();

            builder.Property(e => e.Foto)
                .HasColumnType("varbinary(max)")
                .IsRequired(false);

            builder.Property(x => x.Cpf)
              .HasColumnType("varchar(14)")
              .IsRequired();


            builder.Property(x => x.Cep)
             .HasColumnType("varchar(10)")
             .IsRequired();

            builder.Property(x => x.Endereco)
             .HasColumnType("varchar(255)")
             .IsRequired();

            builder.Property(x => x.Numero)
             .HasColumnType("int")
             .IsRequired();

            builder.Property(x => x.Bairro)
             .HasColumnType("varchar(100)")
             .IsRequired();

            builder.Property(x => x.Estado)
             .HasColumnType("varchar(50)")
             .IsRequired();

            builder.Property(x => x.DataNacimento)
             .HasColumnType("date")
             .IsRequired();
        }
    }
}

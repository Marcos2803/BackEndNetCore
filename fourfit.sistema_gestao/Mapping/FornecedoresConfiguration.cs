using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Mapping
{
    public class FornecedoresConfiguration : IEntityTypeConfiguration<Fornecedores>
    {
        public void Configure(EntityTypeBuilder<Fornecedores> builder)
        {
            builder.ToTable("Fornecedores");
            builder.HasKey("Id");

            builder.Property(x => x.NomeFornecedor)
           .HasColumnType("varchar(100)")
           .IsRequired();

            builder.Property(x => x.Status)
            .HasColumnType("varchar(10)")
            .IsRequired();
   
            builder.Property(x => x.Tipo)
           .HasColumnType("varchar(100)")
           .IsRequired();

            builder.Property(x => x.CpfCnpj)
             .HasColumnType("varchar(18)")
             .IsRequired();

            builder.Property(x => x.Email)
             .HasColumnType("varchar(50)")
             .IsRequired();

            builder.Property(x => x.Telefone)
              .HasColumnType("varchar(14)")
              .IsRequired();

            builder.Property(x => x.Observacao)
           .HasColumnType("varchar(255)")
           .IsRequired();
        }
    }
}

using fourfit.sistema_gestao.Domain.Entities.EmailConfig;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Mapping
{
    public class EmailConfiguracoesConfiguration : IEntityTypeConfiguration<entidadeEmailConfiguracoes>
    {
        public void Configure(EntityTypeBuilder<entidadeEmailConfiguracoes> builder)
        {
            builder.ToTable("EmailConfiguracoes");
            builder.HasKey(x => x.Id);

            builder.Property(x => x.Smtp)
             .HasColumnType("varchar(100)")
             .IsRequired();

            builder.Property(x => x.Port)
                .IsRequired();

            builder.Property(x => x.EmailUser)
            .HasColumnType("varchar(100)")
            .IsRequired();
        }
    }
}

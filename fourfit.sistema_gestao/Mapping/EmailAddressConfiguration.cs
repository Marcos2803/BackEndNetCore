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
    public class EmailAddressConfiguration : IEntityTypeConfiguration<entidadeEmailAddress>
    {
        public void Configure(EntityTypeBuilder<entidadeEmailAddress> builder)
        {
            builder.ToTable("EmailAddress");
            builder.HasKey(x => x.Id);

            builder.Property(x => x.From)
             .HasColumnType("varchar(100)")
             .IsRequired();

            builder.Property(x => x.To)
             .HasColumnType("varchar(100)")
             .IsRequired();

            builder.Property(x => x.Subject)
             .HasColumnType("varchar(500)")
             .IsRequired();

            builder.Property(x => x.Body)
             .HasColumnType("varchar(500)")
             .IsRequired();
        }
    }
}

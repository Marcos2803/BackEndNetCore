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
    public class EmailPasswordAccountConfiguration : IEntityTypeConfiguration<entidadeEmailPasswordAccount>
    {
        public void Configure(EntityTypeBuilder<entidadeEmailPasswordAccount> builder)
        {
            builder.ToTable("EmailPasswordAccount");

            builder.HasKey(x => x.Id);

            builder.Property(x => x.Password)
                .HasColumnType("varchar(Max)")
                .IsRequired();
        }
    }
}

﻿using fourfit.sistema_gestao.Domain.Entities.Financas;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;


namespace fourfit.sistema_gestao.Mapping
{
    public class DespesasConfiguration : IEntityTypeConfiguration<Despesas>
    {
        public void Configure(EntityTypeBuilder<Despesas> builder)
        {
            builder.ToTable("Despesas");
            builder.HasKey(x => x.Id);

            builder.HasOne(x => x.FormaPagamento)
               .WithMany(a => a.Despesas)
               .HasForeignKey(a => a.FormaPagamentoId);

            builder.HasOne(x => x.ContasBancarias)
               .WithMany(a => a.Despesas)
               .HasForeignKey(a => a.ContasBancariasId);

            builder.HasOne(x => x.TipoDespesas)
               .WithMany(a => a.Despesas)
               .HasForeignKey(a => a.TipoDespesasId);

            builder.Property(x => x.Descricao)
            .HasColumnType("varchar(50)")
             .IsRequired();

            builder.Property(x => x.ValorDespesa)
             .HasColumnType(" decimal(18, 2)")
             .IsRequired();

            builder.Property(x => x.DataVencimento)
             .HasColumnType("date")
             .IsRequired();

            builder.Property(x => x.DataPagamento)
             .HasColumnType("date")
             .IsRequired();

            builder.Property(x => x.StatusPagamentos)
             .HasColumnType("varchar(10)")
             .IsRequired();

            builder.Property(x => x.Observacao)
                .HasColumnType("varchar(100)")
                .IsRequired();
        }
    }
}

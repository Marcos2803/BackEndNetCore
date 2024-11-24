using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Mapping;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Context
{
    public class DataContext : IdentityDbContext<User>
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {


        }
        // Dataset


        #region Tabelas
         public DbSet<User> Usuarios { get; set; }
        public DbSet<EntidadeAlunos> Alunos { get; set; }
        public DbSet<EntidadeProfessores> Professores { get; set; }
        public DbSet<EntidadeColaboradores> Colaboradores { get; set; }
        public DbSet<Checkins> Checkins { get; set; }
        public DbSet<Horarios> Horarios { get; set; }
        public DbSet<Mensalidades> Mensalidades { get; set; }
        public DbSet<Modalidades> Modalidades { get; set; }
        public DbSet<Parcelas> ParcelaMensalidades { get; set; }
        public DbSet<AvaliacaoFisica> AvaliacaoFisica { get; set; }
        public DbSet<Parq> Parq { get; set; }
        public DbSet<TipoPlano> Planos { get; set; }
        public DbSet<AulaExperimental> AulaExperimental { get; set; }


        public DbSet<Despesas> Despesas { get; set; }
        public DbSet<TipoDespesas> TipoDespesas { get; set; }
        public DbSet<Investimentos> Investimentos { get; set; }
        public DbSet<Fornecedores> Fornecedores { get; set; }
        public DbSet<ContasBancarias> ContasBancarias { get; set; }
        public DbSet<Impostos> Impostos { get; set; }

        public DbSet<Produtos> Produtos { get; set; }
        public DbSet<Categorias> Categorias { get; set; }
        public DbSet<Estoque> ControleEstoque { get; set; }
        public DbSet<Vendas> Vendas { get; set; }
        public DbSet<VendaItens> VendaItens { get; set; }
        public DbSet<Pagamentos> Pagamentos { get; set; }
        public DbSet<FormaPagamento> FormaPagamento { get; set; }

        //public DbSet<entidadeEmailConfiguracoes>? EmailConfiguracoes { get; set; }
        //public DbSet<entidadeEmailAddress>? EmailAddress { get; set; }
        //public DbSet<entidadeEmailPasswordAccount>? EmailPasswordAccount { get; set; }
        //public DbSet<AlunosPesquisa> AlunosPesquisa { get; set; }


        #endregion
        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<User>(new UserConfiguration().Configure);
            builder.Entity<EntidadeAlunos>(new AlunosConfiguration().Configure);
            builder.Entity<EntidadeProfessores>(new ProfessoresConfiguration().Configure);
            builder.Entity<EntidadeColaboradores>(new ColaboradoresConfiguration().Configure);
            builder.Entity<Checkins>(new CheckinsConfiguration().Configure);
            builder.Entity<Horarios>(new HorariosConfiguration().Configure);
            builder.Entity<Mensalidades>(new MensalidadesConfiguration().Configure);
            builder.Entity<Parcelas>(new ParcelasConfiguration().Configure);
            builder.Entity<Modalidades>(new ModalidadesConfiguration().Configure);
            builder.Entity<AvaliacaoFisica>(new AvaliacaoFisicaConfiguration().Configure);
            builder.Entity<Parq>(new ParqConfiguration().Configure);
            builder.Entity<PersonalRecord>(new PersonalRecordConfiguration().Configure);
            builder.Entity<TipoPlano>(new TipoPlanoConfiguration().Configure);
            builder.Entity<AulaExperimental>(new AulaExperimentalConfiguration().Configure);


            builder.Entity<Despesas>(new DespesasConfiguration().Configure);
            builder.Entity<TipoDespesas>(new TipoDespesasConfiguration().Configure);
            builder.Entity<Investimentos>(new InvestimentosConfiguration().Configure);
            builder.Entity<Fornecedores>(new FornecedoresConfiguration().Configure);
            builder.Entity<Impostos>(new ImpostosConfiguration().Configure);
            builder.Entity<ContasBancarias>(new ContasBancariasConfiguration().Configure);

            builder.Entity<Produtos>(new ProdutosConfiguration().Configure);
            builder.Entity<Categorias>(new CategoriasConfiguration().Configure);
            builder.Entity<Estoque>(new EstoqueConfiguration().Configure);
            builder.Entity<Vendas>(new VendasConfiguration().Configure);
            builder.Entity<VendaItens>(new VendaItensConfiguration().Configure);
            builder.Entity<Pagamentos>(new PagamentosConfiguration().Configure);
            builder.Entity<FormaPagamento>(new FormaPagamentoConfiguration().Configure);

            base.OnModelCreating(builder);
        }
    }
}
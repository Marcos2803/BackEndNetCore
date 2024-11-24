using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;


namespace fourfit.sistema_gestao.Repositories.Repository.Financas
{
    public class PagamentosRepository : BaseRepository<Pagamentos>, IPagamentosServices
    {
        private readonly DataContext _dataContext;

        public PagamentosRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Pagamentos>> ObterPagamentosExistentes()
        {
            var resultado = await _dataContext.Set<Pagamentos>()
              .Include(x => x.FormaPagamento)
              .Include(x => x.ContasBancarias)
              .Include(x => x.Vendas)
              .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<Pagamentos> ObterPagamentosPorId(int Id)
        {
            var resultado = await _dataContext.Set<Pagamentos>()
             .Include(x => x.FormaPagamento).Where(x => x.Id == Id)
             .Include(x => x.Vendas).Where(x => x.Id == Id)
             .Include(x => x.ContasBancarias).Where(x => x.Id == Id)
             .FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;
        }

    }
}

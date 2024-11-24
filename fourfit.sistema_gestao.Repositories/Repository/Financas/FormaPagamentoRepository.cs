using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;


namespace fourfit.sistema_gestao.Repositories.Repository.Financas
{
    public class FormaPagamentoRepository : BaseRepository<FormaPagamento>, IFormaPagamentoServices
    {
        private readonly DataContext _dataContext;
        public FormaPagamentoRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public Task<IEnumerable<FormaPagamento>> ObterFormaPagamentoExistentes()
        {
            throw new NotImplementedException();
        }

        public async Task<FormaPagamento> ObterFormaPagamentoPorId(int? Id)
        {

            return await _dataContext.Set<FormaPagamento>().FindAsync(Id);
        }
    }
}

using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Financas
{
    public class InvestimentosRepository : BaseRepository<Investimentos>, IInvestimentosServices
    {
        private readonly DataContext _dataContext;

        public InvestimentosRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<Investimentos>> ObterInvestimentosExistentes()

        {

            var resultado = await _dataContext.Set<Investimentos>()
                .Include(x => x.Id)
                //.Include(x => x.Pagamento)
                .Include(x => x.Descricao)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }
    }
}
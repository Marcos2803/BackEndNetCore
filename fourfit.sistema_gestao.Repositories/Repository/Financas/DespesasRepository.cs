using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Financas
{
    public class DespesasRepository : BaseRepository<Despesas>, IDespesasServices
    {
        private readonly DataContext _dataContext;

        public DespesasRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<Despesas>> ObterDespesasExistentes()

        {

            //var resultado = await _dataContext.Set<Despesas>()
            //    .Include(x => x.Id)
            //    .Include(x => x.Pagamento)
            //    .Include(x => x.Descricao)
            //    .ToListAsync();

            //if (resultado != null)
            //{
            //    return resultado;
            //}

            return null;
        }
    }
}

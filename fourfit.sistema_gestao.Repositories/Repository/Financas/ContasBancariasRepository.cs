using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;

namespace fourfit.sistema_gestao.Repositories.Repository.Financas
{
    public class ContasBancariasRepository : BaseRepository<ContasBancarias>, IContasBancariasServices
    {
        private readonly DataContext _dataContext;
        public ContasBancariasRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public Task<IEnumerable<ContasBancarias>> ObterContasBancariasExistentes()
        {
            throw new NotImplementedException();
        }

        public async Task<ContasBancarias> ObterContasBancariasPorId(int? Id)
        {

            return await _dataContext.Set<ContasBancarias>().FindAsync(Id);
        }
    }
}
